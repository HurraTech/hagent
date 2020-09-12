package main
import (
    "context"
    "syscall"
    "flag"
    "fmt"
    "net"
    "os"
    "strings"
    "strconv"
    "os/exec"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "github.com/jaypipes/ghw"
    
    log "github.com/sirupsen/logrus"
    pb "hurracloud.io/agent/proto"

)

var (
    tls        = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
    certFile   = flag.String("cert_file", "", "The TLS cert file")
    keyFile    = flag.String("key_file", "", "The TLS key file")
    jsonDBFile = flag.String("json_db_file", "", "A json file containing a list of features")
    listen     = flag.String("listen", "127.0.0.1", "Which interface IP to listen on")
    port       = flag.Int("port", 10000, "The server port")
    uid        = flag.Int("uid", -1, "Run commands using this user ID")
    jawharUid  = flag.Int("jawharUid", 1000, "UID to be given access to mounted drives")
)

type hurraAgentServer struct {
    pb.UnimplementedHurraAgentServer
}

// Returns list of drives and their partitions
func (s *hurraAgentServer) GetDrives(ctx context.Context, drive *pb.GetDrivesRequest) (*pb.GetDrivesResponse, error) {
    log.Info("Request to Get Drives")
    block, err := ghw.Block()
    if err != nil {
        error := fmt.Errorf("Error getting block storage info:", err)
        log.Error(error)
        return nil, error
    }

    log.Debug("Retrieved Block Storage Info:", block)

    response := &pb.GetDrivesResponse{}
    for _, disk := range block.Disks {
        log.Debug("Found Disk: ", disk)
        drive := &pb.Drive{
            Name: disk.Name,
            DeviceFile: "/dev/" + disk.Name,
            SizeBytes: disk.SizeBytes,
            IsRemovable: disk.IsRemovable,
            Type: disk.DriveType.String(),
            SerialNumber: disk.SerialNumber,
            StorageController: disk.StorageController.String(),
        }
        response.Drives = append(response.Drives, drive)
        for _, partition := range disk.Partitions {
            log.Debug("Found Partition: ", partition)
            partition := &pb.Partition{
                Name: partition.Name,
                DeviceFile: "/dev/" + partition.Name,
                SizeBytes: partition.SizeBytes,
                Filesystem: partition.Type,
                MountPoint: partition.MountPoint,
                IsReadOnly: partition.IsReadOnly,
                AvailableBytes: 0,
            }

            // Determine available space (if partition is mounted, no way to know otherwise)
            if partition.MountPoint != "" {
                log.Debugf("Partition %s is mounted. Attempting to find free space.", partition.Name)
                cmd := exec.Command("sh", "-c", fmt.Sprintf("df %s | tail -n +2 | awk '{print $4}'", partition.DeviceFile))
                output, err := cmd.Output()
                if err == nil {
                    freespace, err := strconv.ParseUint(strings.Trim(string(output), "\n"), 10, 64)
                    if err == nil {
                        partition.AvailableBytes = freespace
                        log.Debugf("Determined Available Bytes for %v to be %v", partition.Name, partition.AvailableBytes)
                    } else {
                        log.Errorf("Could not parse df command output: %s: %s", output, err)
                    }
                } else {
                    log.Errorf("Could not determine mounted partition free space %v", err)
                }
            } 

            if partition.Filesystem == "" {
                //ghw does not return Filesystem for unmounted partition, attempt to find it on our own
                log.Debug("Attempt to find Filesystem for Partition ", partition.Name)
                cmd := exec.Command("sh", "-c", fmt.Sprintf("lsblk -o fstype %s | tail -n +2", partition.DeviceFile))
                output, err := cmd.Output()
                if err == nil {
                    partition.Filesystem = strings.Trim(string(output), "\n")
                    log.Debugf("Determined Filesystem of %v is %v", partition.Name, partition.Filesystem)
                }

            }

            // ghw does not return labels, attempt to find it on our own 
            log.Debug("Attempt to find Label for Partition ", partition.Name)
            cmd := exec.Command("sh", "-c", fmt.Sprintf("lsblk -o label %s | tail -n +2", partition.DeviceFile))
            output, err := cmd.Output()
            if err == nil {
                partition.Label = strings.Trim(string(output), "\n")
                log.Debugf("Determined Label of %v is %v", partition.Name, partition.Label)
            }

            drive.Partitions = append(drive.Partitions, partition)
        }
    }
    return response, nil
}

// Mount specified device on specified mount point.
// Create mount point if not already exists
// Grant read/write access to non-root users (jawharUid)
func (s *hurraAgentServer) MountDrive(ctx context.Context, drive *pb.MountDriveRequest) (*pb.MountDriveResponse, error) {
    log.Info("Request to Mount %s at %s", drive.DeviceFile, drive.MountPoint)
    response := &pb.MountDriveResponse{IsSuccessful: true}
    var mountArgs = []string{drive.DeviceFile, drive.MountPoint, "-o", fmt.Sprintf("umask=0022,uid=%d,gid=%d", *jawharUid, *jawharUid)}
    var error, err error
    var out []byte
    var cmd *exec.Cmd

    // Create mount point if it does not exist
    _, err = os.Stat(drive.MountPoint)
    if os.IsNotExist(err) {
        log.Printf("Mount point %s does not exist. Creating it now.", drive.MountPoint)
        errDir := os.MkdirAll(drive.MountPoint, 0755)
        if errDir != nil {
            response.Errors = append(response.Errors, fmt.Sprintf("Failed to create mount point: %s (%s)", drive.MountPoint, errDir.Error()))
            response.IsSuccessful = false
            goto failed
        }
    }

    // Attempt to mount using default options
    log.Printf("Attempting to mount with %s default options", drive.DeviceFile)

    // First try with default options
    cmd = exec.Command("mount", mountArgs...)
    log.Debug("Running command: %v", cmd)
    out, err = cmd.CombinedOutput()
    if err != nil {
        // Default options failed
        log.Printf("Failed to mount %s with default options: %s", drive.DeviceFile, err.Error())
        log.Printf("Mounting using %s ntfs-3g", drive.DeviceFile)
        response.Errors = append(response.Errors, fmt.Sprintf("Mount command failed [default options]: %s (%s)", out, err.Error() ) )

        // Try with ntfs-3g driver
        mountArgs = append(mountArgs, "-t", "ntfs-3g")
        cmd = exec.Command("mount", mountArgs...)
        out, err = cmd.CombinedOutput()
        if err != nil {
            log.Printf("Failed to mount %s using ntfs-3g: %s", drive.DeviceFile, err.Error())
            response.Errors = append(response.Errors, fmt.Sprintf("Mount command failed [ntfs-3g]: %s (%s)", out, err.Error() ) )
            response.IsSuccessful = false
        }
    }

failed: 
    if response.IsSuccessful != true {
        error = fmt.Errorf("All mount attempts failed: %s", response.Errors)
        log.Printf("Mount failed: %s", error)
    }

    return response, error
}


// Mount specified device on specified mount point.
// Create mount point if not already exists
// Grant read/write access to non-root users (jawharUid)
func (s *hurraAgentServer) UnmountDrive(ctx context.Context, drive *pb.UnmountDriveRequest) (*pb.UnmountDriveResponse, error) {
    log.Info("Request to Unmount %s", drive.DeviceFile)
    response := &pb.UnmountDriveResponse{IsSuccessful: true}
    var umountArgs = []string{drive.DeviceFile}
    var error, err error
    var out []byte
    var cmd *exec.Cmd

    // Attempt to mount using default options
    log.Printf("Attempting to unmount with %s", drive.DeviceFile)

    // First try with default options
    cmd = exec.Command("umount", umountArgs...)
    log.Debug("Running command: %v", cmd)
    out, err = cmd.CombinedOutput()
    if err != nil {
        log.Printf("Failed to unmount %s: %s", drive.DeviceFile, err.Error())
        response.Error = fmt.Sprintf("Umount command failed: %s (%s)", out, err.Error())
        error = fmt.Errorf(response.Error)        
        response.IsSuccessful = false
    }

    return response, error
}


// ExecCommand returns the feature at the given point.
func (s *hurraAgentServer) ExecCommand(ctx context.Context, command *pb.Command) (*pb.Result, error) {
    cmd := exec.Command("bash", "-c", command.Command)
    cmd.SysProcAttr = &syscall.SysProcAttr{}
    if (*uid != -1) {
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
    return result,nil
}

func newServer() *hurraAgentServer {
    s := &hurraAgentServer{}
    return s
}

func main() {
    flag.Parse()
    log.SetLevel(log.DebugLevel)
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
    grpcServer := grpc.NewServer(opts...)
    pb.RegisterHurraAgentServer(grpcServer, newServer())
    grpcServer.Serve(lis)
}
