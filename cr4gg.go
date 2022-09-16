package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/crypto/pbkdf2"
)

var ssid []byte
var ANonce []byte
var SNonce []byte
var APMac net.HardwareAddr
var ClientMac net.HardwareAddr
var firstMIC []byte
var micData []byte
var verboseMode bool

func handleFirstMessage(packet gopacket.Packet) {
	if dot11 := packet.Layer(layers.LayerTypeDot11); dot11 != nil {
		dot11, _ := dot11.(*layers.Dot11)
		APMac = dot11.Address1
		ClientMac = dot11.Address2
	}

	if eapolLayer := packet.Layer(layers.LayerTypeEAPOLKey); eapolLayer != nil {
		eapol, _ := eapolLayer.(*layers.EAPOLKey)
		ANonce = eapol.Nonce
	}
}

func handleSecondMessage(packet gopacket.Packet) {
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOLKey); eapolLayer != nil {
		eapolKeyFrame, _ := eapolLayer.(*layers.EAPOLKey)
		SNonce = eapolKeyFrame.Nonce

		tmp := eapolKeyFrame.MIC
		cpy := make([]byte, len(tmp))
		copy(cpy, tmp)
		firstMIC = cpy

		if verboseMode {
			fmt.Printf("1. MIC: %x \n", firstMIC)
		}
	}

	if dot11 := packet.Layer(layers.LayerTypeDot11); dot11 != nil {
		dot11, _ := dot11.(*layers.Dot11)
		dot11Payload := dot11.LayerPayload()[8:]
		zero := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		micData = append(append(dot11Payload[:81], zero...), dot11Payload[97:]...)
	}

}

func handleThirdMessage(packet gopacket.Packet) {
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOLKey); eapolLayer != nil {
		eapol, _ := eapolLayer.(*layers.EAPOLKey)

		aNonceEqualsSigned := reflect.DeepEqual(eapol.Nonce, ANonce)
		if !aNonceEqualsSigned {
			panic("ANonce does not match with the signed Nonce in third Handshake message.")
		}

		if verboseMode {
			fmt.Printf("2. MIC: %x \n", eapol.MIC)
		}
	}

}

func handleFourthMessage(packet gopacket.Packet) {
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOLKey); eapolLayer != nil {
		eapol, _ := eapolLayer.(*layers.EAPOLKey)

		if verboseMode {
			fmt.Printf("3. MIC: %x \n", eapol.MIC)
		}
	}
}

func generatePMKFromPassphrase(phrase string) []byte {
	pmk := pbkdf2.Key([]byte(phrase), []byte(ssid), 4096, 256, sha1.New)[:32]
	return pmk
}

func byteMin(u []byte, v []byte) []byte {
	if bytes.Compare(u, v) < 0 {
		return u
	}
	return v
}

func byteMax(u []byte, v []byte) []byte {
	if bytes.Compare(u, v) > 0 {
		return u
	}
	return v
}

func generateB(apMac []byte, clientMac []byte, aNonce []byte, sNonce []byte) []byte {
	// Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce)
	res := make([]byte, 0)

	res = append(res, byteMin(apMac, clientMac)...)
	res = append(res, byteMax(apMac, clientMac)...)
	res = append(res, byteMin(aNonce, sNonce)...)
	res = append(res, byteMax(aNonce, sNonce)...)

	return res
}

// PRF-X(...); X := bitlength
// PRF-X(PMK, "Pairwise key expansion", (Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce)))
func PRFX(key []byte, a []byte, b []byte, x int) []byte {
	var r []byte
	byteLen := x / 8
	y := []byte{byte(0x00)}

	// HMAC-SHA-1(K, A || Y || B || i)
	for i := 0; i < (x+159)/160; i++ {
		data := append(append(append(a, y...), b...), []byte{byte(i)}...)
		mac := hmac.New(sha1.New, key)
		mac.Write(data)
		r = append(r, mac.Sum(nil)...)
	}
	return r[:byteLen]
}

func main() {
	// Parse Flags
	var pcapString string
	var passFileString string
	var ssidString string
	flag.StringVar(&ssidString, "ssid", "", "number of lines to read from the file")
	flag.StringVar(&passFileString, "w", "", "file path of wordlist")
	flag.StringVar(&pcapString, "f", "", "file path of pcap")
	verboseFlag := flag.Bool("v", false, "output in verbose mode")
	flag.Parse()
	verboseMode = *verboseFlag

	if len(strings.TrimSpace(ssidString)) == 0 {
		fmt.Println("Please provide an SSID via -ssid <SSID>")
		os.Exit(1)
	}
	ssid = []byte(ssidString)

	// Packet Capture
	filename := pcapString
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	// Word List
	file, err := os.Open(passFileString)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// First Packet
	packet, err := packetSource.NextPacket()
	if err != nil {
		panic("Failed getting the first packet.")
	}
	handleFirstMessage(packet)

	// Second Packet
	packet, err = packetSource.NextPacket()
	if err != nil {
		panic("Failed getting the second packet.")
	}
	handleSecondMessage(packet)

	// Third Packet
	packet, err = packetSource.NextPacket()
	if err != nil {
		panic("Failed getting the third packet.")
	}
	handleThirdMessage(packet)

	// Fourth Packet
	packet, err = packetSource.NextPacket()
	if err != nil {
		panic("Failed getting the fourth packet.")
	}
	handleFourthMessage(packet)

	for scanner.Scan() {
		password := scanner.Text()
		pmk := generatePMKFromPassphrase(password)

		// Min(AA,SPA) || Max(AA,SPA) || Min(ANonce,SNonce) || Max(ANonce,SNonce)
		b := generateB([]byte(APMac), []byte(ClientMac), ANonce, SNonce)
		ptk := PRFX(pmk, []byte("Pairwise key expansion"), b, 512)

		if verboseMode {
			fmt.Printf("ANonce: %x \n", ANonce)
			fmt.Printf("SNonce: %x \n", SNonce)
			fmt.Printf("AP-MAC Address: %x\n", []byte(APMac))
			fmt.Printf("Client-MAC Address: %x\n", []byte(ClientMac))
			fmt.Println()
			fmt.Println("Password:", password)
			fmt.Printf("PMK: %x\n", pmk)
			fmt.Printf("PTK: %x\n", ptk)
		}

		hmacFunc := sha1.New                // WPA2
		mac := hmac.New(hmacFunc, ptk[:16]) // KCK = first 16 bytes
		mac.Write(micData)
		mic := mac.Sum(nil)

		if bytes.Compare(mic[:16], firstMIC) == 0 {
			fmt.Println("Correct Password:", password)
			break
		}
	}
}
