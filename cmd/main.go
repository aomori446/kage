package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	
	"github.com/aomori446/kage"
	"github.com/aomori446/kage/config"
)

func runMockServer(m config.Mode, addr string) {
	if m == config.ModeTCP {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}
		defer ln.Close()
		
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go func() {
				defer conn.Close()
				
				buf := make([]byte, 100)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						log.Println(err)
						return
					}
					if string(buf[:n]) == "ping" {
						_, err := conn.Write([]byte("pong"))
						if err != nil {
							log.Println(err)
							return
						}
					}
				}
			}()
		}
	}
	
	packet, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer packet.Close()
	
	buf := make([]byte, 100)
	for {
		n, addr, err := packet.ReadFrom(buf)
		if err != nil {
			log.Println(err)
			return
		}
		
		if string(buf[:n]) == "ping" {
			_, err := packet.WriteTo([]byte("pong"), addr)
			if err != nil {
				log.Println(err)
				return
			}
		}
	}
}

func main() {
	listenAddr := "127.0.0.1:3333"
	forwardAddr := "127.0.0.1:4444"
	serverAddr := "127.0.0.1:5555"
	mode := config.ModeUDP
	protocol := config.ProtocolTunnel
	fastOpen := true
	password := "rwQc8qPXVsRpGx3uW+Y3Lj4Y42yF9Bs0xg1pmx8/+bo="
	method := config.CipherMethod2022blake3aes256gcm
	
	cfg := &config.Config{
		ListenAddr:   listenAddr,
		ForwardAddr:  forwardAddr,
		ServerAddr:   serverAddr,
		Mode:         mode,
		Protocol:     protocol,
		FastOpen:     fastOpen,
		Password:     password,
		CipherMethod: method,
	}
	
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	
	go runMockServer(mode, forwardAddr)
	
	err := kitsune.RunClient(ctx, nil, cfg)
	if err != nil {
		log.Fatal(err)
	}
}
