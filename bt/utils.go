package bt

import (
	"bytes"
	"errors"
	"io/ioutil"
	"log"
)

const (
	// ERROR - constant for an error
	ERROR = iota
	// ELF - constant for ELF binary format
	ELF = iota
	// MACHO - constant for Mach-O binary format
	MACHO = iota
	// FAT - constant for FAT/Mach-O binary format
	FAT = iota
	// PE - constant for PE binary format
	PE = iota
	// MIN_CAVE_SIZE - the smallest a code cave can be
	MIN_CAVE_SIZE = 94
)

// BinaryMagic - Identifies the Binary Format of a file by looking at its magic number
func BinaryMagic(filename string) (int, error) {

	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return ERROR, err
	}

	log.Printf("%x\n", buf[:4])

	if bytes.Equal(buf[:4], []byte{0x7F, 'E', 'L', 'F'}) {
		log.Printf("ELF\n")
		return ELF, nil
	}

	if bytes.Equal(buf[:3], []byte{0xfe, 0xed, 0xfa}) {
		if buf[3] == 0xce || buf[3] == 0xcf {
			// FE ED FA CE - Mach-O binary (32-bit)
			// FE ED FA CF - Mach-O binary (64-bit)
			log.Printf("MACHO\n")
			return MACHO, nil
		}
	}

	if bytes.Equal(buf[1:4], []byte{0xfa, 0xed, 0xfe}) {
		if buf[0] == 0xce || buf[0] == 0xcf {
			// CE FA ED FE - Mach-O binary (reverse byte ordering scheme, 32-bit)
			// CF FA ED FE - Mach-O binary (reverse byte ordering scheme, 64-bit)
			log.Printf("MACHO\n")
			return MACHO, nil
		}
	}

	if bytes.Equal(buf[:3], []byte{0xca, 0xfe, 0xba}) {
		if buf[3] == 0xbe || buf[3] == 0xbf {
			log.Printf("FAT\n")
			return FAT, nil
		}
	}

	if bytes.Equal(buf[1:4], []byte{0xba, 0xfe, 0xca}) {
		if buf[0] == 0xbe || buf[0] == 0xbf {
			log.Printf("FAT\n")
			return FAT, nil
		}
	}

	if bytes.Equal(buf[:2], []byte{0x4d, 0x5a}) {
		log.Printf("PE\n")
		return PE, nil
	}

	return ERROR, errors.New("Unknown Binary Format")
}
