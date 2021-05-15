package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jaypipes/ghw"
	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mackerelio/go-osstat/memory"
	"github.com/mackerelio/go-osstat/network"
	"github.com/mackerelio/go-osstat/uptime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	log "github.com/sirupsen/logrus"
	"hurracloud.io/agent/disk"
	pb "hurracloud.io/agent/proto"
)

var (
	tls        = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile   = flag.String("cert_file", "", "The TLS cert file")
	keyFile    = flag.String("key_file", "", "The TLS key file")
	jsonDBFile = flag.String("json_db_file", "", "A json file containing a list of features")
	listen     = flag.String("listen", "127.0.0.1", "Which interface IP to listen on")
	tmpDir     = flag.String("tmp_dir", "", "Where to store temp files (default: system's tmp dircetory)")
	port       = flag.Int("port", 10000, "The server port")
	uid        = flag.Int("uid", -1, "Run commands using this user ID")
	jawharUid  = flag.Int("jawharUid", 1000, "UID to be given access to mounted drives")
	verbose    = flag.Bool("verbose", false, "Enable verbose logging")
)

type hurraAgentServer struct {
	pb.UnimplementedHurraAgentServer
	updateState string
}

// Returns list of drives and their partitions
func (s *hurraAgentServer) GetDrives(ctx context.Context, drive *pb.GetDrivesRequest) (*pb.GetDrivesResponse, error) {
	log.Tracef("Request to Get Drives")
	block, err := ghw.Block()
	if err != nil {
		error := fmt.Errorf("Error getting block storage info: %v", err)
		log.Error(error)
		return nil, error
	}

	log.Trace("Retrieved Block Storage Info:", block)

	response := &pb.GetDrivesResponse{}
	for _, disk := range block.Disks {
		log.Trace("Found Disk: ", disk)
		drive := &pb.Drive{
			Name:              disk.Name,
			DeviceFile:        "/dev/" + disk.Name,
			SizeBytes:         disk.SizeBytes,
			IsRemovable:       disk.IsRemovable,
			Type:              disk.DriveType.String(),
			SerialNumber:      disk.SerialNumber,
			Vendor:            disk.Vendor,
			StorageController: disk.StorageController.String(),
		}
		response.Drives = append(response.Drives, drive)
		var index uint32 = 0
		for _, partition := range disk.Partitions {
			log.Trace("Found Partition: ", partition)
			if partition.MountPoint == "" {
				// last-resort attempt to find mountpoint if ghw fails to detect it
				cmd := exec.Command("lsblk", "/dev/"+partition.Name, "-o", "MOUNTPOINT", "-n")
				output, err := cmd.Output()
				if err == nil {
					partition.MountPoint = strings.Trim(string(output), "\n")
				}
			}

			partition := &pb.Partition{
				Index:          index,
				Name:           partition.Name,
				DeviceFile:     "/dev/" + partition.Name,
				SizeBytes:      partition.SizeBytes,
				Filesystem:     partition.Type,
				MountPoint:     partition.MountPoint,
				IsReadOnly:     partition.IsReadOnly,
				AvailableBytes: 0,
			}
			index++

			// Determine available space (if partition is mounted, no way to know otherwise)
			if partition.MountPoint != "" {
				log.Tracef("Partition %s is mounted at '%s'. Attempting to find free space.", partition.Name, partition.MountPoint)
				cmd := exec.Command("sh", "-c", fmt.Sprintf("df -h %s | tail -n +2 | awk '{print $4}'", partition.MountPoint))
				output, err := cmd.Output()
				if err == nil {
					freespace, err := strconv.ParseUint(strings.Trim(strings.Trim(string(output), "Gi\n"), "G"), 10, 64)
					if err == nil {
						partition.AvailableBytes = freespace * uint64(math.Pow(1024, 3))
						log.Tracef("Determined Available Bytes for %v to be %v", partition.Name, partition.AvailableBytes)
					} else {
						log.Errorf("Could not parse df command output: %s: %s", output, err)
					}
				} else {
					log.Errorf("Could not determine mounted partition free space %v", err)
				}
			}

			if partition.Filesystem == "" {
				//ghw does not return Filesystem for unmounted partition, attempt to find it on our own
				log.Trace("Attempt to find Filesystem for Partition ", partition.Name)
				cmd := exec.Command("sh", "-c", fmt.Sprintf("lsblk -o fstype %s | tail -n +2", partition.DeviceFile))
				output, err := cmd.Output()
				if err == nil {
					partition.Filesystem = strings.Trim(string(output), "\n")
					log.Tracef("Determined Filesystem of %v is %v", partition.Name, partition.Filesystem)
				}

			}

			// ghw does not return labels, attempt to find it on our own
			log.Trace("Attempt to find Label for Partition ", partition.Name)
			cmd := exec.Command("sh", "-c", fmt.Sprintf("lsblk -o label %s | tail -n +2", partition.DeviceFile))
			output, err := cmd.Output()
			if err == nil {
				partition.Label = strings.Trim(string(output), "\n")
				log.Tracef("Determined Label of %v is %v", partition.Name, partition.Label)
			}

			drive.Partitions = append(drive.Partitions, partition)
		}
	}
	return response, nil
}

// Get system stats such as uptime, cpu load, memory,..etc.
func (s *hurraAgentServer) GetSystemStats(ctx context.Context, drive *pb.GetSystemStatsRequest) (*pb.GetSystemStatsResponse, error) {
	log.Debug("Request to Get System Stats")
	response := &pb.GetSystemStatsResponse{}
	var networks []network.Stats

	// Memory stats
	memory, err := memory.Get()
	if err == nil {
		response.MemoryTotal = memory.Total
		response.MemoryCached = memory.Cached
		response.MemoryFree = memory.Free
	}

	// CPU usage %
	var total float64
	var load float64
	var after *cpu.Stats
	before, err := cpu.Get()
	if err != nil {
		log.Errorf("Could not get cpu stats, skipping: %s", err)
		goto network_stats
	}
	time.Sleep(time.Duration(1) * time.Second)
	after, err = cpu.Get()
	if err != nil {
		log.Errorf("Could not get cpu stats, skipping: %s", err)
		goto network_stats
	}
	total = float64(after.Total - before.Total)
	load = float64(after.User-before.User) + float64(after.System-before.System)
	response.LoadAverage = load / total * 100

network_stats:
	// Network stats
	networks, err = network.Get()
	if err != nil {
		log.Errorf("Could not get network stats, skipping: %s", err)
		goto disk_stats
	}
	for _, net := range networks {
		response.NetworkReceived += net.RxBytes
		response.NetworkSent += net.TxBytes
	}

	// Disk stats
disk_stats:
	disk, err := disk.Get()
	if err == nil {
		log.Debugf("Library returned %v", disk)
		response.DiskReads += disk.ReadsPerSecond
		response.DiskWrites += disk.WritesPerSecond
	} else {
		log.Errorf("Could not get disk stats, skipping it: %s", err)
	}

	// Uptime
	up, err := uptime.Get()
	if err == nil {
		response.Uptime = up.Seconds()
	}

	return response, err
}

// Mount specified device on specified mount point.
// Create mount point if not already exists
// Grant read/write access to non-root users (jawharUid)
func (s *hurraAgentServer) MountDrive(ctx context.Context, drive *pb.MountDriveRequest) (*pb.MountDriveResponse, error) {
	log.Info("Request to Mount %s at %s", drive.DeviceFile, drive.MountPoint)
	response := &pb.MountDriveResponse{IsSuccessful: true}
	var error, err error

	// Create mount point if it does not exist
	_, err = os.Stat(drive.MountPoint)
	if os.IsNotExist(err) {
		log.Printf("Mount point %s does not exist. Creating it now.", drive.MountPoint)
		errDir := os.MkdirAll(drive.MountPoint, 0755)
		if errDir != nil {
			log.Errorf("Failed to create mount point: %s (%s)", drive.MountPoint, errDir)
			return nil, errDir
		}
	}

	// Attempt to mount using default options
	log.Infof("Attempting to mount with %s", drive.DeviceFile)

	// First try with default options
	var options string
	if drive.Filesystem == "ntfs" || drive.Filesystem == "ext3" {
		options = fmt.Sprintf("umask=0022,uid=%d,gid=%d", *jawharUid, *jawharUid)
	}
	_, err = exec.Command("mount", "-o", options, drive.DeviceFile, drive.MountPoint).Output()

	if err != nil {
		// Default options failed
		log.Errorf("Failed to mount %s: %s", drive.DeviceFile, err)
		return nil, err
	}

	// Let's add to fstab
	// Grab entry from mtab and copy it for fstab
	cmd := fmt.Sprintf("cat /etc/mtab | grep %s", drive.MountPoint)
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		log.Errorf("Failed to determine mtab entry: %s", cmd)
		return nil, fmt.Errorf("Failed to determine mtab entry: %s", cmd)
	}

	if drive.Filesystem != "ntfs" {
		errDir := os.Chmod(drive.MountPoint, 0755)
		if errDir != nil {
			log.Errorf("Failed to update permissions on mount point %s to uid %d: %v", drive.MountPoint, *jawharUid, errDir)
			return nil, errDir
		}
	}

	f, err := os.OpenFile("/etc/fstab", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Errorf("Failed to open fstab: %s", err)
		return nil, err
	}
	defer f.Close()
	if _, err := f.WriteString(fmt.Sprintf("%s\n", out)); err != nil {
		log.Errorf("Failed to write to fstab: %s", err)
		return nil, err
	}

	return response, error
}

// Mount specified device on specified mount point.
// Create mount point if not already exists
// Grant read/write access to non-root users (jawharUid)
func (s *hurraAgentServer) UnmountDrive(ctx context.Context, drive *pb.UnmountDriveRequest) (*pb.UnmountDriveResponse, error) {
	log.Infof("Request to Unmount %s", drive.MountPoint)
	response := &pb.UnmountDriveResponse{IsSuccessful: true}
	var error, err error

	// Attempt to mount using default options
	log.Infof("Attempting to unmount %s", drive.MountPoint)

	err = syscall.Unmount(drive.MountPoint, 0)
	if err != nil {
		log.Printf("Failed to unmount %s: %s", drive.MountPoint, err)
		return nil, err
	}

	// Let's remove from fstab
	f, err := os.OpenFile("/etc/fstab", os.O_RDONLY, 0644)
	if err != nil {
		log.Errorf("Failed to open fstab for reading: %s", err)
		return nil, err
	}
	fstabLines, err := ioutil.ReadAll(f)
	if err != nil {
		log.Errorf("Failed to read fstab: %s", err)
		return nil, err
	}
	re := regexp.MustCompile(fmt.Sprintf("(?m)[\r\n]+^.*%s.*$", strings.ReplaceAll(drive.MountPoint, "/", "\\/")))
	newFstab := re.ReplaceAll(fstabLines, []byte(""))
	err = f.Close()
	if err != nil {
		log.Errorf("Failed to close fstab read file descriptor: %s", err)
		return nil, err
	}

	f, err = os.OpenFile("/etc/fstab", os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Errorf("Failed to open fstab for writing: %s", err)
		return nil, err
	}
	defer f.Close()

	log.Debugf("Writing to /etc/fstab: %s", fstabLines)
	f.Write(newFstab)
	if err != nil {
		log.Errorf("Failed to write new entry to fstab: %s", err)
		return nil, err
	}

	return response, error
}

// LoadImage load container image.
func (s *hurraAgentServer) LoadImage(ctx context.Context, req *pb.LoadImageRequest) (*pb.LoadImageResponse, error) {
	log.Debugf("Downloading image %s", req.URL)
	tmpDirectory, err := filepath.Abs(*tmpDir)
	if err != nil {
		return nil, fmt.Errorf("Could not determine absolute path for temp directory: %s: %v", *tmpDir, err)
	}

	// Open tmp file for writing image to
	if _, err := os.Stat(tmpDirectory); os.IsNotExist(err) {
		err := os.MkdirAll(tmpDirectory, 0755)
		if err != nil {
			return nil, fmt.Errorf("Could not create temp directory: %s: %v", tmpDirectory, err)
		}
	}

	img, err := ioutil.TempFile(tmpDirectory, "image")
	if err != nil {
		return nil, fmt.Errorf("Could not create temp file: %s", err)
	}
	log.Debugf("Writing to %s", img.Name())
	defer img.Close()
	defer os.Remove(img.Name())

	// Open image url
	httpReq, err := http.NewRequest("GET", req.URL, nil)
	if err != nil {
		log.Errorf("Error opening HTTP request: %s", err)
		return nil, fmt.Errorf("Error opening HTTP request: %s", err)
	}

	httpReq.SetBasicAuth(req.Username, req.Password)
	client := &http.Client{}
	resp, err := client.Do(httpReq)

	if err != nil {
		return nil, fmt.Errorf("Could not open URL: %s: %s", req.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Image server returned bad status: %s", resp.Status)
	}

	_, err = io.Copy(img, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error downloading image: %s: %s", req.URL, err)
	}

	// Load image in docker daemon
	log.Debugf("Loading image in Docker")
	cmd := exec.Command("docker", "load", "-i", img.Name())
	out, err := cmd.CombinedOutput()
	strOut := strings.Replace(string(out), "\n", " ", -1)
	if err != nil {
		log.Errorf("Failed to load image. Command Output: %s", strOut)
		return nil, fmt.Errorf("Error loading image: %s", err)
	}
	log.Debugf("Done. Output: '%s'", strOut)

	return &pb.LoadImageResponse{}, nil
}

func (s *hurraAgentServer) UnloadImage(ctx context.Context, req *pb.UnloadImageRequest) (*pb.UnloadImageResponse, error) {
	log.Debugf("Unloading image %s", req.Tag)

	// Load image in docker daemon
	cmd := exec.Command("docker", "rmi", req.Tag)
	out, err := cmd.CombinedOutput()
	strOut := strings.Replace(string(out), "\n", " ", -1)
	if err != nil {
		if !strings.Contains(strOut, "No such image") {
			log.Errorf("Failed to remove image. Command Output: %s", strOut)
			return nil, fmt.Errorf("Error unloading image: %s", err)
		} else {
			log.Warningf("Image %s already did not exist", req.Tag)
		}
	}
	log.Debugf("Done. Output: '%s'", strOut)

	return &pb.UnloadImageResponse{}, nil
}

// Run single container.
func (s *hurraAgentServer) RunContainer(ctx context.Context, req *pb.RunContainerRequest) (*pb.RunContainerResponse, error) {
	log.Debugf("Running container image %s with name %s and port mapping %d:%d", req.Image, req.Name, req.PortMappingSource, req.PortMappingTarget)

	// Start containers
	log.Debugf("Run containers")
	cmdArgs := []string{"run", "--rm", "-d", "--name", req.Name,
		"-p", fmt.Sprintf("%d:%d", req.PortMappingSource, req.PortMappingTarget),
		"--add-host", "host.docker.internal:host-gateway"}
	for _, env := range strings.Split(req.Env, ",") {
		cmdArgs = append(cmdArgs, "-e", env)
	}
	cmdArgs = append(cmdArgs, req.Image)
	cmd := exec.Command("docker", cmdArgs...)
	out, err := cmd.CombinedOutput()
	strOut := strings.Replace(string(out), "\n", " ", -1)
	if err != nil {
		log.Errorf("Failed to start container. Command Output: %s", strOut)
		return nil, fmt.Errorf("Error starting containers: %s. Output: %s", err, strOut)
	}
	log.Debugf("Container Started. Output: '%s'", strOut)

	// Connect container to app network
	if false {
		//TODO: Re-enable if there's value in connecting UI app to app containers network
		log.Debugf("Connect container to app network")
		cmd = exec.Command("docker", "network", "connect", fmt.Sprintf("%s_%s", req.Name, req.Name), req.Name)
		out, err = cmd.CombinedOutput()
		strOut = strings.Replace(string(out), "\n", " ", -1)
		if err != nil {
			log.Errorf("Failed to connect container to network. Command Output: %s", strOut)
			return nil, fmt.Errorf("Error starting containers: %s. Output: %s", err, strOut)
		}
		log.Debugf("Container network connected. Output: '%s'", strOut)
	}

	return &pb.RunContainerResponse{}, nil
}

// Kill single container
func (s *hurraAgentServer) KillContainer(ctx context.Context, req *pb.KillContainerRequest) (*pb.KillContainerResponse, error) {
	log.Debugf("Killing container %s", req.Name)

	// Kill container
	cmd := exec.Command("docker", "kill", req.Name)
	out, err := cmd.CombinedOutput()
	strOut := strings.Replace(string(out), "\n", " ", -1)

	if strings.Contains(strOut, "is not running") {
		log.Warningf("Container %s was stoppe. Removing it.", req.Name)
		cmd := exec.Command("docker", "rm", req.Name)
		out, err = cmd.CombinedOutput()
		strOut = strings.Replace(string(out), "\n", " ", -1)
	}

	if err != nil {
		if !strings.Contains(strOut, "No such container") {
			log.Errorf("Failed to kill container. Command Output: %s", strOut)
			return nil, fmt.Errorf("Error starting containers: %s. Output: %s", err, strOut)
		} else {
			log.Warningf("Container %s did not exist or was already killed", req.Name)
		}
	}
	log.Debugf("Done. Output: '%s'", strOut)

	return &pb.KillContainerResponse{}, nil
}

// Run container spec (docker compose file).
func (s *hurraAgentServer) RunContainerSpec(ctx context.Context, req *pb.ContainerSpecRequest) (*pb.ContainerSpecResponse, error) {
	log.Debugf("Running containers at root context %s", req.Context)
	composeFilename := fmt.Sprintf("%s.yaml", req.Name)

	// Create file to write componse file contents to
	err := ioutil.WriteFile(path.Join(req.Context, composeFilename), []byte(req.Spec), 0644)
	if err != nil {
		return nil, fmt.Errorf("Could not write to compose file: %s", err)
	}

	// Start containers
	log.Debugf("Start containers")
	cmd := exec.Command("docker-compose", "-f", composeFilename, "-p", req.Name, "up", "-d")
	cmd.Dir = req.Context
	out, err := cmd.CombinedOutput()
	strOut := strings.Replace(string(out), "\n", " ", -1)
	if err != nil {
		log.Errorf("Failed to start containers. Command Output: %s", strOut)
		return nil, fmt.Errorf("Error starting containers: %s. Output: %s", err, strOut)
	}
	log.Debugf("Done. Output: '%s'", strOut)

	return &pb.ContainerSpecResponse{}, nil
}

// Find port binding in container spec
func (s *hurraAgentServer) GetContainerPortBindingInSpec(ctx context.Context, req *pb.ContainerPortBindingInSpecRequest) (*pb.ContainerPortBindingInSpecResponse, error) {
	log.Debugf("Determing port binding of container %s/%s/%d", req.Name, req.ContainerName, req.ContainerPort)
	composeFilename := fmt.Sprintf("%s.yaml", req.Name)

	// Open tmp file for writing image to
	err := ioutil.WriteFile(path.Join(req.Context, composeFilename), []byte(req.Spec), 0644)
	if err != nil {
		return nil, fmt.Errorf("Could not write to compose file: %s", err)
	}

	// Start containers
	log.Debugf("Start containers")
	cmd := exec.Command("docker-compose", "-f", composeFilename, "-p", req.Name, "port", req.ContainerName, fmt.Sprintf("%d", req.ContainerPort))
	cmd.Dir = req.Context
	out, err := cmd.CombinedOutput()
	strOut := strings.Replace(string(out), "\n", " ", -1)
	strOut = strings.TrimSpace(strOut)
	log.Debugf("Running %v", cmd)
	if err != nil {
		log.Errorf("Failed to start containers. Command Output: %s", strOut)
		return nil, fmt.Errorf("Error starting containers: %s. Output: %s", err, strOut)
	}
	portMapping := strings.Split(strOut, ":")
	if len(portMapping) != 2 {
		log.Errorf("Unexpected output from docker-compose port command (%d). Command Output: %s", len(portMapping), strOut)
		return nil, fmt.Errorf("Error determining port: Unexpected output from docker-compose port command. Command Output: %s", strOut)

	}
	port, err := strconv.Atoi(portMapping[1])
	if err != nil {
		log.Errorf("Failed to parse docker port output: %s: %s", strOut, err)
		return nil, fmt.Errorf("Failed to parse docker port output: %s: %s", strOut, err)
	}

	log.Debugf("Done. Output: '%s'. Port: %d", strOut, port)

	return &pb.ContainerPortBindingInSpecResponse{PortBinding: uint32(port)}, nil
}

// Stop containers
func (s *hurraAgentServer) StopContainerSpec(ctx context.Context, req *pb.ContainerSpecRequest) (*pb.ContainerSpecResponse, error) {
	log.Debugf("Running containers at root context %s", req.Context)
	composeFilename := fmt.Sprintf("%s.yaml", req.Name)

	// Start containers
	log.Debugf("Stop containers")
	cmd := exec.Command("docker-compose", "-f", composeFilename, "-p", req.Name, "stop")
	cmd.Dir = req.Context
	out, err := cmd.CombinedOutput()
	strOut := strings.Replace(string(out), "\n", " ", -1)
	if err != nil {
		log.Errorf("Failed to stop containers. Command Output: %s", strOut)
		return nil, fmt.Errorf("Error stopping containers: %s. Output: %s", err, strOut)
	}
	log.Debugf("Done. Output: '%s'", strOut)

	return &pb.ContainerSpecResponse{}, nil
}

// Remove containers
func (s *hurraAgentServer) RemoveContainerSpec(ctx context.Context, req *pb.ContainerSpecRequest) (*pb.ContainerSpecResponse, error) {
	log.Debugf("Running containers at root context %s", req.Context)
	composeFilename := fmt.Sprintf("%s.yaml", req.Name)

	// Remove containers
	log.Debugf("Stop containers")
	cmd := exec.Command("docker-compose", "-f", composeFilename, "-p", req.Name, "down", "-v")
	cmd.Dir = req.Context
	out, err := cmd.CombinedOutput()
	strOut := strings.Replace(string(out), "\n", " ", -1)
	if err != nil {
		log.Errorf("Failed to remove containers. Command Output: %s", strOut)
		return nil, fmt.Errorf("Error remove containers: %s. Output: %s", err, strOut)
	}
	log.Debugf("Done. Output: '%s'", strOut)

	return &pb.ContainerSpecResponse{}, nil
}

// Exec command in a container
func (s *hurraAgentServer) ExecInContainerSpec(ctx context.Context, req *pb.ExecInContainerSpecRequest) (*pb.ExecInContainerSpecResponse, error) {
	log.Debugf("Exec command request. Container=%s. Command=%s, Env=%s", req.ContainerName, req.Cmd, req.Env)
	composeFilename := fmt.Sprintf("%s.yaml", req.Name)

	cmdArgs := []string{"-f", composeFilename, "-p", req.Name, "exec"}

	// Prepand -e KEY=VAL before exec command arg
	envMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(req.Env), &envMap)
	if err != nil {
		log.Errorf("Error parsing env map: %s", err)
		return nil, fmt.Errorf("Error parsing env map: %s: %s", req.Env, err)
	}

	for key, val := range envMap {
		cmdArgs = append(cmdArgs, "-e", fmt.Sprintf("%s=%s", key, val))
	}

	// Append -T containerName COMMAND
	cmdArgs = append(cmdArgs, "-T", req.ContainerName, req.Cmd)

	// Append command ARGS
	var argList []string
	err = json.Unmarshal([]byte(req.Args), &argList)
	if err != nil {
		log.Errorf("Error parsing args list: %s", err)
		return nil, fmt.Errorf("Error parsing args list: %s: %s", req.Args, err)
	}

	for _, val := range argList {
		cmdArgs = append(cmdArgs, val)
	}

	cmd := exec.Command("docker-compose", cmdArgs...)

	log.Debugf("Executing in container %s/%s: %v", req.Cmd, req.Name, req.ContainerName, cmd)
	cmd.Dir = req.Context
	out, err := cmd.CombinedOutput()
	strOut := strings.Replace(string(out), "\n", " ", -1)
	if err != nil {
		log.Errorf("Failed to exec in container. Command Output: %s", strOut)
		return nil, fmt.Errorf("Error exec in container: %s. Output: %s", err, strOut)
	}
	log.Debugf("Done. Output: '%s'", strOut)

	return &pb.ExecInContainerSpecResponse{Output: string(out)}, nil
}

// Stop a specific container in a container spec file
func (s *hurraAgentServer) StopContainerInSpec(ctx context.Context, req *pb.ContainerSpecRequest) (*pb.ContainerSpecResponse, error) {
	log.Debugf("Stop container in sepc request. Spec=%s. Container=%s", req.Name, req.ContainerName)
	composeFilename := fmt.Sprintf("%s.yaml", req.Name)

	cmd := exec.Command("docker-compose", "-f", composeFilename, "-p", req.Name, "stop", req.ContainerName)

	cmd.Dir = req.Context
	out, err := cmd.CombinedOutput()
	strOut := strings.Replace(string(out), "\n", " ", -1)
	if err != nil {
		log.Errorf("Failed to stop container. Command Output: %s", strOut)
		return nil, fmt.Errorf("Error stopping container: %s. Output: %s", err, strOut)
	}
	log.Debugf("Done. Output: '%s'", strOut)

	return &pb.ContainerSpecResponse{}, nil
}

// Start a specific container in a container spec file
func (s *hurraAgentServer) StartContainerInSpec(ctx context.Context, req *pb.ContainerSpecRequest) (*pb.ContainerSpecResponse, error) {
	log.Debugf("Start container in sepc request. Spec=%s. Container=%s", req.Name, req.ContainerName)
	composeFilename := fmt.Sprintf("%s.yaml", req.Name)

	cmd := exec.Command("docker-compose", "-f", composeFilename, "-p", req.Name, "start", req.ContainerName)

	cmd.Dir = req.Context
	out, err := cmd.CombinedOutput()
	strOut := strings.Replace(string(out), "\n", " ", -1)
	if err != nil {
		log.Errorf("Failed to start container. Command Output: %s", strOut)
		return nil, fmt.Errorf("Error stopping container: %s. Output: %s", err, strOut)
	}
	log.Debugf("Done. Output: '%s'", strOut)

	return &pb.ContainerSpecResponse{}, nil
}

// ExecCommand returns the feature at the given point.
func (s *hurraAgentServer) ExecCommand(ctx context.Context, command *pb.Command) (*pb.Result, error) {
	cmd := exec.Command("bash", "-c", command.Command)
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	if *uid != -1 {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(*uid), Gid: uint32(*uid)}
	}
	out, err := cmd.CombinedOutput()
	exitCode := int32(0)
	if err != nil {
		out = []byte(err.Error())
		exitCode = 1
	}
	log.Printf("Command: %s. Output: %s", command.Command, out)
	result := &pb.Result{Message: string(out), ExitCode: exitCode}
	return result, nil
}

// UpdateSystem updates system image to specified version using mender
func (s *hurraAgentServer) UpdateSystem(ctx context.Context, req *pb.UpdateSystemRequest) (*pb.UpdateSystemResult, error) {
	log.Infof("Update state is: %s", s.updateState)
	if s.updateState == "in-progress" {
		// update is already in progress
		return nil, fmt.Errorf("update in-progress")
	}

	tmpDirectory, err := filepath.Abs(*tmpDir)
	if err != nil {
		return nil, fmt.Errorf("Could not determine absolute path for temp directory: %s: %v", *tmpDir, err)
	}

	log.Infof("Downloading image %s [%s] to %s", req.ImageUrl, req.Hash, tmpDirectory)

	// Open tmp file for writing image to
	if _, err := os.Stat(tmpDirectory); os.IsNotExist(err) {
		err := os.MkdirAll(tmpDirectory, 0755)
		if err != nil {
			return nil, fmt.Errorf("Could not create temp directory: %s: %v", tmpDirectory, err)
		}
	}

	img, err := ioutil.TempFile(tmpDirectory, "hurraos.mender")
	if err != nil {
		return nil, fmt.Errorf("Could not create temp file: %s", err)
	}
	log.Debugf("Writing to %s", img.Name())

	// Open image url
	httpReq, err := http.NewRequest("GET", req.ImageUrl, nil)
	if err != nil {
		log.Errorf("Error opening HTTP request: %s", err)
		return nil, fmt.Errorf("Error opening HTTP request: %s", err)
	}

	httpReq.SetBasicAuth(req.Username, req.Password)
	client := &http.Client{}
	resp, err := client.Do(httpReq)

	if err != nil {
		return nil, fmt.Errorf("Could not open URL: %s: %s", req.ImageUrl, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Image server returned bad status: %s", resp.Status)
	}
	_, err = io.Copy(img, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error downloading image: %s: %s", req.ImageUrl, err)
	}

	// Check sha sum
	img.Close()
	img, err = os.Open(img.Name())
	if err != nil {
		return nil, fmt.Errorf("Error opening downloaded img for integrity validation: %s: %v", img.Name(), err)
	}

	hasher := sha1.New()
	_, err = io.Copy(hasher, img)
	if err != nil {
		return nil, fmt.Errorf("Error computing hash of donwloaded image: %s", err)
	}
	sha1sum := hex.EncodeToString(hasher.Sum(nil))

	if sha1sum != req.Hash {
		log.Errorf("Download image's SHA1 sum does not match expected SHA1 sum: %s != %s", sha1sum, req.Hash)
	}

	log.Infof("SHA1 sum check successful")

	// Execute install
	go func(s *hurraAgentServer) {
		s.updateState = "in-progress"
		log.Debugf("Updating system using mender")
		cmd := exec.Command("mender", "install", img.Name())
		out, err := cmd.CombinedOutput()
		strOut := strings.Replace(string(out), "\n", " ", -1)
		if err != nil {
			log.Errorf("Failed to install image. Command Output: %s", strOut)
			s.updateState = "error"
		}
		log.Debugf("Done. Output: '%s'", strOut)
		s.updateState = "success"
	}(s)

	return &pb.UpdateSystemResult{}, nil
}

// UpdateSystemStatus updates system image to specified version using mender
func (s *hurraAgentServer) UpdateSystemStatus(ctx context.Context, req *pb.UpdateSystemStatusRequest) (*pb.UpdateSystemResult, error) {
	cmd := exec.Command("mender", "show-artifact")
	out, err := cmd.CombinedOutput()
	strOut := strings.Replace(string(out), "\n", " ", -1)
	if err != nil {
		log.Errorf("Failed to checking current version. Command Output: %s", strOut)
		return nil, fmt.Errorf("Failed to checking current version. Command Output: %s", strOut)
	}
	log.Debugf("Done. Output: '%s'", strOut)

	return &pb.UpdateSystemResult{Status: s.updateState, Version: strOut}, nil
}

func newServer() *hurraAgentServer {
	s := &hurraAgentServer{}
	return s
}

func main() {
	flag.Parse()
	if *verbose {
		log.SetLevel(log.TraceLevel)
	}
	lis, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *listen, *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if *tls {
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	log.Infof("Starting server on %s:%d", *listen, *port)
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterHurraAgentServer(grpcServer, newServer())
	grpcServer.Serve(lis)
}
