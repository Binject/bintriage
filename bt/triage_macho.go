package bt

import (
	"log"

	"github.com/Binject/debug/macho"
)

// MachoBinTriage - Get more info on a Mach-O binary
func MachoBinTriage(sourceFile string) error {
	machoFile, err := macho.Open(sourceFile)
	if err != nil {
		return err
	}

	// Macho Header
	log.Println(cyan.Printf("your macho header: %+v", machoFile.FileHeader))

	// Load Commands
	for _, singleLoad := range machoFile.Loads {
		log.Println(blue.Sprintf("Single Load Command: %+v", singleLoad))
	}

	// Sections
	for _, section := range machoFile.Sections {
		log.Println(cyan.Sprintf("Section details: %+v", section))
	}

	// Symbols
	for _, symbol := range machoFile.Symtab.Syms {
		log.Println(cyan.Sprintf("Symbol details: %+v", symbol))
	}

	// SymTab
	log.Println(blue.Sprintf("SymTab: %+v", machoFile.Symtab))

	// DySymTab
	if machoFile.Dysymtab != nil {
		log.Println(cyan.Sprintf("DySymTab Infos: %+v", machoFile.Dysymtab))
	}

	// Write Dynamic Loader Info if it exists
	if machoFile.DylinkInfo != nil {
		log.Println(blue.Sprintf("Dynamic Loader Infos: %+v", machoFile.DylinkInfo))
	}

	// FuncStarts
	if machoFile.FuncStarts != nil {
		log.Println(cyan.Sprintf("Func Starts Infos: %+v", machoFile.FuncStarts))
	}

	// DataInCode
	if machoFile.DataInCode != nil {
		log.Println(blue.Printf("DataInCode deets: %+v", machoFile.DataInCode))
	}

	// StringTab
	//if machoFile.Symtab.RawStringtab != nil {
	//	log.Println(blue.Sprintf("StringTab deets: %+v", machoFile.Symtab.RawStringtab))
	//}

	if machoFile.SigBlock != nil {
		log.Println(cyan.Printf("Sigblock: %+v", machoFile.SigBlock))
	}

	//dwarf, err := machoFile.DWARF()
	//if err != nil {
	//	log.Fatal(err)
	//}
	//log.Printf("Dwarf details: %+v", dwarf)

	libraries, err := machoFile.ImportedLibraries()
	if err != nil {
		log.Fatal(red.Sprintf(err.Error()))
	}
	for _, ilib := range libraries {
		log.Println(cyan.Sprintf("Imported lib details: %+v", ilib))
	}

	impSymbs, err := machoFile.ImportedSymbols()
	if err != nil {
		log.Fatal(red.Sprintf(err.Error()))
	}
	for _, isymb := range impSymbs {
		log.Println(blue.Sprintf("Imported symbol details: %+v", isymb))
	}

	return nil
}
