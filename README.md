# ISA - Generování NetFlow dat ze zachycené síťové komunikace

Úkolem bylo vyvtořit NetFlow exportér, který ze zachycených síťových dat ve formátu pcap vytvoří záznamy NetFlow, které odešle na kolektor.

# Autor

Lukáš Kaprál(xkapra00)

# Datum

08.10.2022

## Odevzdané soubory

```
$ flow.c - obsahuje implementaci načítání a zpracování packetů
$ argparse.c - obsahuje funkci pro zpracování argumentů
$ argparse.h - obsahuje definice struktur
$ Makefile - umožňuje překlad programu pomocí příkazu make
$ flow.1 - obsahuje manuál k projektu
$ manual.pdf - dokumentace projektu
```

## Použití

```
$ Před spuštěním použijeme příkaz make
$ Pro spuštění zadáme příkaz ./flow [-f soubor] [-a active timer] [-i inactive timer] [-m flow cache size] [-c netflow colllector]
```