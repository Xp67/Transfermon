# Transfermon

App Windows (Rust) che trasferisce **file, impostazioni e programmi** da un PC a un altro sulla stessa rete locale. Si avvia la stessa app sui due computer: si trovano da sole, si agganciano con un codice a 6 cifre e il PC vecchio riversa tutto sul PC nuovo attraverso un canale cifrato, senza passare da internet.

## Come si usa

1. Avvia `transfermon.exe` su entrambi i PC (stessa rete Wi-Fi o cavo). Alla prima apertura Windows chiede il permesso per il firewall: consenti l'accesso alle **reti private**.
2. Sul **PC nuovo** scegli *Questo è il PC NUOVO*: compare il codice di collegamento (e l'indirizzo IP, per l'inserimento manuale).
3. Sul **PC vecchio** scegli *Questo è il PC VECCHIO*, seleziona il PC nuovo nell'elenco (o scrivi l'indirizzo), inserisci il codice, spunta cosa inviare e premi *Avvia trasferimento*.
4. Sul PC nuovo compare il riepilogo (quanti file, dove verranno scritti): premi *Accetta e avvia*.
5. A fine trasferimento, sul PC nuovo, premi *Installa i programmi con winget*: si apre una finestra che reinstalla i programmi del vecchio PC. L'elenco completo dei programmi (anche quelli che winget non conosce) è in `%LOCALAPPDATA%\Transfermon\app\<pc>-<data>\programmi-installati.txt`.

Il trasferimento si può **ripetere**: i file già presenti e identici (stessa dimensione e data) non vengono ritrasmessi, quindi un'interruzione non fa ripartire da zero.

## Cosa viene trasferito

| Voce | Cosa contiene | Default |
|---|---|---|
| Desktop, Documenti, Download, Immagini, Musica, Video | Le cartelle note dell'utente, anche se spostate in OneDrive (i file *solo online* vengono saltati, non scaricati). | sì |
| Altri file del profilo | Il resto di `C:\Users\<nome>`: `.ssh`, `.gitconfig`, Preferiti, Contatti, Giochi salvati, progetti… Esclusi OneDrive, AppData, `NTUSER.*`, `.docker`, `.rustup`, `.cache`, le cache di cargo/NuGet/Gradle. | sì |
| Impostazioni delle app | `AppData\Roaming`: profili e preferenze di browser, Office, Discord, Thunderbird… | sì |
| Dati locali delle app | `AppData\Local`: dati più voluminosi (Chrome/Edge, VS Code, programmi installati per l'utente). Escluse cache, `Temp`, Docker, app dello Store (`Packages`), cache grafiche. | no |
| Cartelle aggiuntive | Qualsiasi cartella (es. `D:\Progetti`): sul PC nuovo finisce nello **stesso percorso**; se il disco non esiste, in `C:\Users\<nome>\Transfermon\Disco_D\…`. | — |
| Elenco programmi | Programmi dal registro di Windows + `winget export`. | sì |

Le cartelle note vengono rimappate sul profilo del PC nuovo anche se il nome utente è diverso.

## I programmi

Windows non permette di copiare un programma installato (registro, servizi, licenze). Transfermon quindi:

- sul PC vecchio legge l'elenco dei programmi dal registro ed esegue `winget export`;
- sul PC nuovo salva elenco ed export e prepara `installa-app.cmd`, che lancia `winget import` (reinstalla le versioni attuali dai repository winget e Microsoft Store, chiedendo le autorizzazioni di Windows);
- i programmi che winget non riconosce restano nell'elenco testuale per l'installazione manuale;
- le impostazioni personali dei programmi arrivano con la copia di AppData.

Limiti: licenze e attivazioni vanno rifatte; le credenziali protette con DPAPI (password salvate nei browser, token) non sono leggibili su un'altra macchina; i programmi installati solo per l'utente in `AppData\Local\Programs` vengono copiati come file ma conviene comunque reinstallarli.

## Sicurezza

- Il codice a 6 cifre non viaggia mai in rete: i due PC ricavano una chiave di sessione con **SPAKE2** e la confermano con un hash. Codice sbagliato = chiavi diverse = connessione rifiutata; dopo 3 tentativi errati il PC nuovo genera un nuovo codice.
- Tutto il traffico dopo il pairing è cifrato e autenticato con **ChaCha20-Poly1305** (nonce = direzione + contatore).
- I percorsi ricevuti sono validati: niente `..`, niente percorsi assoluti nelle cartelle note.
- Il PC nuovo scrive solo dopo che l'utente ha accettato il riepilogo.

## Rete

- Ricerca: beacon UDP in broadcast sulla porta **47831** ogni secondo (anche sui broadcast diretti di ogni interfaccia).
- Trasferimento: TCP sulla porta **47832** (o una porta casuale se occupata; viene mostrata sotto il codice).
- Se la ricerca automatica non funziona (firewall, VLAN, reti ospiti), usa l'indirizzo manuale `ip:porta` mostrato sul PC nuovo.

## Compilare

Servono Rust (toolchain MSVC) e Visual Studio Build Tools.

```sh
cargo build --release
# eseguibile: target/release/transfermon.exe (nessuna dipendenza esterna, basta copiarlo sui due PC)
```

Test (trasferimento completo fra due istanze in-process, pairing con codice sbagliato, esclusioni di scansione, mappatura percorsi):

```sh
cargo test
```

In build `debug` l'app tiene aperta anche la console con i log; in `release` scrive su `%LOCALAPPDATA%\Transfermon\transfermon.log`.

Per aprire direttamente una schermata (comodo in sviluppo): `transfermon sender` oppure `transfermon receiver`.

## Aspetto

Un foglio bianco su carta grigio-azzurra, pensato per sembrare affidabile a chi sta cambiando computer:

- un solo colore d'azione (petrolio `#0F6F8F`) per il pulsante principale, le selezioni e la barra di avanzamento; verde per il completato, rosso per gli errori; tutto il resto è inchiostro `#1C2733` su bianco, con il testo secondario in grigio `#5E6B78`;
- niente ombre né gradienti: la gerarchia la fanno dimensione e peso del carattere, le sezioni sono separate da righe sottili, i numeri stanno in colonna;
- Segoe UI dai font di Windows (Semibold per titoli e codice di collegamento, Regular per il testo, Bold per le enfasi) e Cascadia Mono per i percorsi; se mancano si usano i font di egui;
- l'unico elemento vistoso è il codice di collegamento, a 72 px sul PC nuovo;
- nessuna animazione oltre allo spinner e al riempimento della barra.

Tutto sta in [src/theme.rs](src/theme.rs).

## Struttura

```
src/
  main.rs              avvio eframe
  ui.rs                interfaccia (schermata iniziale, PC vecchio, PC nuovo)
  theme.rs             aspetto metallizzato: texture, font, pulsanti, sfondo
  lib.rs
  discovery.rs         beacon UDP e elenco dei PC trovati
  secure.rs            pairing SPAKE2 + canale cifrato
  protocol.rs          messaggi e radici logiche
  scan.rs              scansione cartelle con esclusioni
  dest.rs              mappatura percorsi sul PC nuovo
  transfer.rs          invio / ricezione
  receiver_service.rs  listener TCP del PC nuovo
  apps.rs              registro programmi, winget export/import
  shared.rs            stato condiviso fra thread e interfaccia
  sysinfo.rs           cartelle note, nome PC, IP
tests/roundtrip.rs     trasferimento completo in-process
```
