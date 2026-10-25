# Partner's NUCLEO: matching secure server

This kit contains the server that matches the client already provisioned on Board A. It is built for **NUCLEO-WL55JC**. No LoRaWAN AppKey or flash dump is included.

## Quick flash with STM32CubeProgrammer

1. Attach the NUCLEO-WL55JC2 using its ST-LINK USB port and a data cable.
2. In STM32CubeProgrammer, select ST-LINK/SWD and connect to that board. If several boards are attached, select the intended board's probe serial explicitly.
3. Open `firmware/server/zephyr.hex`, download/program it, verify it, then reset/run the board.
4. Open its ST-LINK virtual serial port at **115200 baud**. Reset to capture the boot messages.
5. Expect `Provisioned signing identity self-test PASS`, `Crypto self-test PASS`, and `Secure LoRa SERVER ready`. When the client is powered nearby with the course-supplied antennas attached, the handshake should progress and the server should print `DELIVER seq=...: ESE5180 secure hello #...` once per sequence. Duplicate packets are acknowledged without duplicate deliveries.

Actual two-board communication has not yet been verified. Save both serial logs. To demonstrate recovery, restart one endpoint and confirm that the other eventually starts a fresh handshake; handshake silence triggers a reset after one minute. Ordinary retry intervals are 8 seconds; each data sequence is transmitted at least twice.

## Rebuild if needed

The source tree includes the server, shared protocol/application, the exact Crypto library, and the server's local identity header. Keep this matched identity when rebuilding. Regenerating identities for just one board breaks the public-key pin on the other board.

Use the handout's Zephyr 4.4-or-newer environment, SDK 1.0.1 and west. On macOS/Linux, with your usual Zephyr workspace at `~/zephyrproject` and SDK at `~/zephyr-sdk-1.0.1`, run:

```bash
bash build.sh server
```

Override `LAB_ZEPHYR_WORKSPACE` or `LAB_ZEPHYR_SDK` if yours are elsewhere. The build script stages source in a path without spaces and prints the server build directory. On Windows, copy `lab2_security/` to a path without spaces and use the normal `west build -b nucleo_wl55jc` command from your Zephyr workspace.

The prepared HEX is the current matched image; its SHA-256 is in `SERVER-SHA256.txt`. The kit includes the server's lab signing identity because it is needed to reproduce that exact image. Keep the kit within your group; the private identity header is deliberately excluded from normal Git tracking.

The Section 3 physical cloning experiment uses a different **full flash image**, not this server HEX. Do not use this kit as evidence for that experiment.
