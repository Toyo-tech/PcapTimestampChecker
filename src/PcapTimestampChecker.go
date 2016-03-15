package main

import (
	"github.com/Lukasa/gopcap"
	"os"
	"fmt"
	"time"
	"flag"
	"io/ioutil"
	"path"
)

func CheckError(err error) bool {
	 if err != nil {
		fmt.Println("ERROR :", err)
		return true
	}
	return false
}

// Parse pcap file and check timestamp
func CheckTimeStamp(filename string, threshold time.Duration){
	pcapFile, err:= os.Open(filename)
	if CheckError(err){
		return
	}
	
	parsedPcap, err := gopcap.Parse(pcapFile)
	if CheckError(err){
		pcapFile.Close()
		return
	}
	
	lastPacketTime := parsedPcap.Packets[0].Timestamp
	for i, packet := range parsedPcap.Packets {
		if packet.Timestamp - lastPacketTime > threshold{
			fmt.Println("Time stamp missing is detected between", i , " and ",i + 1," in",filename)
		}
		lastPacketTime = packet.Timestamp
	}
	pcapFile.Close()
}

func main(){
	filename := flag.String("f","*.pcap","[pcapfile] : set pcap file name if you want to check specified file")
	threshold := flag.Int("t",-1, "[us] : set threshold")
	flag.Parse()
	
	if *threshold < 0{
		println("Please input valid time threshold with option -t.")
		return
	}
	
	thresholdTime := time.Duration(*threshold) * time.Microsecond
	
	// Analyze one file.
	if *filename != "*.pcap" {
		CheckTimeStamp(*filename,thresholdTime)
		return
	}
	
	//get the current directory path
	currentDirectory,err := os.Getwd()
	if CheckError(err){
		return
	}
	
	//get file list info in the current directory 
	fileInfos, err := ioutil.ReadDir(currentDirectory)
	if CheckError(err){
		return
	}
	
	//check .pcap file in the current directory
	for _,fileInfo := range fileInfos{
		currentFileName := fileInfo.Name()
		matched, err := path.Match("*.pcap",currentFileName)
		if CheckError(err){
			continue
		}
		
		if !matched {
			continue
		}
		
		CheckTimeStamp(currentFileName,thresholdTime)
	}
}


	