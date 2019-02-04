package bt

import (
	"log"

	"github.com/Binject/debug/pe"
)

// PeBinTriage - get more info on a PE binary
func PeBinTriage(sourceFile string) error {
	peFile, err := pe.Open(sourceFile)
	if err != nil {
		return err
	}

	// Header deets
	log.Println(cyan.Printf("DosHeader: %+v", peFile.DosHeader))
	log.Println(blue.Printf("Rich Hdeader: %+v", peFile.RichHeader))
	log.Println(cyan.Printf("Pe Header: %+v", peFile.FileHeader))
	log.Println(blue.Printf("Optional Header: %+v", peFile.OptionalHeader))

	for _, section := range peFile.Sections {
		log.Println(cyan.Printf("Section details: %+v", section))
	}

	for _, symbol := range peFile.Symbols {
		log.Println(blue.Printf("Symbol details: %+v", symbol))
	}

	libraries, err := peFile.ImportedLibraries()
	if err != nil {
		log.Fatal(err)
	}
	for _, ilib := range libraries {
		log.Println(cyan.Printf("Imported lib details: %+v", ilib))
	}

	impSymbs, err := peFile.ImportedSymbols()
	if err != nil {
		log.Fatal(err)
	}
	for _, isymb := range impSymbs {
		log.Println(blue.Printf("Imported symbol details: %+v", isymb))
	}

	// COFFSymbols
	log.Println(cyan.Printf("Coff symbols: %+v", peFile.COFFSymbols))

	// String Table
	//log.Println(blue.Printf("String Table: %+v", peFile.StringTable))

	// the certificate table
	//if peFile.CertificateTable != nil {
	//	log.Println(cyan.Printf("Cert Table: %+v", peFile.CertificateTable))
	//}

	return nil
}
