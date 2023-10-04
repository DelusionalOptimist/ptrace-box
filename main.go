package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"

	"golang.org/x/sys/unix"
)

var (
	// constants
	EPERM = uint64(unix.EPERM)
	INVAL = uint64(1)
)

func main() {
	// to check if user has supplied a command to be executed or not
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <cmd> <args>...\n", os.Args[0])
		os.Exit(1)
	}

	userFilePath, ok := os.LookupEnv("FILE_PATH")
	if !ok {
		fmt.Println("Env var \"FILE_PATH\" must be set...")
		os.Exit(1)
	}

	fmt.Println("Trace: ", os.Args[1:])
	fmt.Println("Block: ", userFilePath)

	// preparing the command to be executed by child process
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin

	cmd.SysProcAttr = &unix.SysProcAttr{
		// this is equivalent of a child calling PTRACE_TRACEME.
		// upon seeing this attribute the internal function which handles fork and
		// exec sends the request
		Ptrace: true,

		// kill the child when parent dies even if the parent is not a tracer
		//Pdeathsig: unix.SIGKILL,
	}

	// certain ptrace requests require control at the OS thread level
	// thus we lock the OS thread so that the Go runtime rescheduling doesn't
	// cause unexpected errors
	// ref: https://github.com/golang/go/issues/7699
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// cmd.Start() is a deep wrapper over syscall.forkexec
	// it forks a new child but since we have set ptrace proc attribute,
	// it stops itself and waits for the tracer before executing
	err := cmd.Start()
	if err != nil {
		fmt.Printf("Failed to create a child: %s\n", err.Error())
		os.Exit(1)
	}
	child := cmd.Process.Pid

	// now we wait for the child to get trapped
	wstatus := new(unix.WaitStatus)
	// we'll be using unix.wait4 as cmd.Wait doesn't handle signals well
	_, err = unix.Wait4(child, wstatus, 0, nil)
	if err != nil {
		fmt.Printf("Failed to wait for child. Err: %s\n", err.Error())
		os.Exit(1)
	}

	if wstatus != nil {
		// tracee has stopped itself by sending a trap signal
		// tracer can now take over
		if wstatus.Stopped() && wstatus.StopSignal() == unix.SIGTRAP {
			fmt.Printf("Tracee (%d) trapped...\n", child)
		}
	} else {
		// if the above's not the case, something is wrong
		fmt.Printf("Tracee (%d) status unknown...\n", child)
		os.Exit(1)
	}

	// PTRACE_O_EXITKILL ensures that tracee gets killed when tracee exits thus
	// preventing jailbreaks. Setting this will have effect only after the child
	// process is trapped for a waiting parent
	unix.PtraceSetOptions(child, unix.PTRACE_O_EXITKILL)

	// start tracing
	err = Trace(child, wstatus, userFilePath)
	if err != nil {
		fmt.Printf("Failed to trace (%d): %s\n", child, err.Error())
		os.Exit(1)
	}

	fmt.Println("Tracer exiting...")
}

func Trace(pid int, status *unix.WaitStatus, userFilePath string) error {
	var (
		err error
		regs unix.PtraceRegs

		// to keep track of syscall entry stops
		// ptrace leaves it upto the tracer to do so
		entry = true
	)

	// let the execve syscall continue
	err = unix.PtraceSyscall(pid, 0)
	if err != nil {
		return err
	}

	// wait for tracee to get trapped on next syscall
	_, err = unix.Wait4(pid, status, 0, nil)
	if err != nil {
		return err
	}

	// trace until tracee doesn't exit
	for !status.Exited() {
		// while the tracee is in a syscall-entry-stop
		// do the needed processing
		if entry {
			err = unix.PtraceGetRegs(pid, &regs)
			if err != nil {
				return err
			}

			err = checkAndBlock(pid, &regs, unix.SYS_OPENAT, userFilePath)
			if err != nil {
				return err
			}
		}

		// resume the tracee execution again
		err = unix.PtraceSyscall(pid, 0)
		if err != nil {
			return err
		}

		// wait for tracee to get trapped again
		_, err = unix.Wait4(pid, status, 0, nil)
		if err != nil {
			return err
		}

		entry = !entry

	}

	fmt.Printf("Tracee (%d) exited...\n", pid)

	return nil
}

func checkAndBlock(pid int, regs *unix.PtraceRegs, syscallNR uint64, userFilePath string) error {
	if regs.Orig_rax == syscallNR {
		// the largest path value that can be stored in the RSI is
		// PATH_MAX bytes long
		buff := make([]byte, unix.PathMax)

		// `PTRACE_PEEKTEXT` request to get file path value from RSI register
		// address in tracee's address space
		n, err := unix.PtracePeekText(pid, uintptr(regs.Rsi), buff)
		if err != nil && n == 0 {
			return err
		}

		// there might be garbage data due to the size of our buffer
		// the string that we need however is null terminated
		nullIdx := bytes.IndexByte(buff[:], 0)

		// get the absolute path w.r.t tracee from the filename
		filePath := absPath(pid, string(buff[:nullIdx]))

		// match file path and set the return value (RAX) as EPERM
		// and Orig_rax to invalid syscall (0)
		// with a PTRACE_SET_REGS request
		if userFilePath == filePath {
			// hacky way to specify a negative u64
			regs.Orig_rax = -INVAL
			regs.Rax = -EPERM
			err := unix.PtraceSetRegs(pid, regs)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// get absolute path
func absPath(pid int, p string) string {
	// if relative path
	if !path.IsAbs(p) {
		return path.Join(getProcCwd(pid), p)
	}
	return path.Clean(p)
}

// read cwd from procfs
func getProcCwd(pid int) string {
	fileName := "/proc/self/cwd"
	if pid > 0 {
		fileName = fmt.Sprintf("/proc/%d/cwd", pid)
	}
	s, err := os.Readlink(fileName)
	if err != nil {
		return ""
	}
	return s
}
