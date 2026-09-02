import subprocess
import shutil
import xml.etree.ElementTree as ET


# ============================================================
# NMAP CONFIGURATION
# ============================================================

# Maximum time allowed for one scan
SCAN_TIMEOUT = 120


# ============================================================
# NMAP SCANNER
# ============================================================

def scan_target(
    target,
    scan_type="standard",
    service_detection=True
):
    """
    Scan an authorized target using Nmap.

    Quick Scan:
        - Nmap's 100 most common ports
        - TCP Connect Scan
        - Skips host discovery
        - Does not require raw socket privileges

    Standard Scan:
        - TCP ports 1-1000
        - TCP Connect Scan
        - Skips host discovery
        - Optional service detection
        - Lightweight version detection

    Returns:
        [
            {
                "port": 80,
                "protocol": "tcp",
                "state": "open",
                "service": "http",
                "product": "...",
                "version": "..."
            }
        ]
    """

    # ========================================================
    # VALIDATE TARGET
    # ========================================================

    if not target:
        raise RuntimeError(
            "No scan target was provided."
        )

    target = str(target).strip()

    if not target:
        raise RuntimeError(
            "Scan target cannot be empty."
        )

    # ========================================================
    # FIND NMAP
    # ========================================================

    nmap_path = shutil.which("nmap")

    if not nmap_path:
        raise RuntimeError(
            "Nmap is not installed or is not available in PATH."
        )

    # ========================================================
    # NORMALIZE SCAN TYPE
    # ========================================================

    scan_type = str(
        scan_type
    ).lower().strip()

    # ========================================================
    # BUILD NMAP ARGUMENTS
    # ========================================================

    if scan_type == "quick":

        # ----------------------------------------------------
        # QUICK SCAN
        # ----------------------------------------------------
        #
        # -Pn
        #     Skip host discovery.
        #
        # -sT
        #     TCP Connect Scan.
        #     Does not require raw socket privileges.
        #
        # -T4
        #     Faster timing.
        #
        # -F
        #     Scan Nmap's 100 most common ports.
        #

        arguments = [
            "-Pn",
            "-sT",
            "-T4",
            "-F"
        ]

    elif scan_type == "standard":

        # ----------------------------------------------------
        # STANDARD SCAN
        # ----------------------------------------------------
        #
        # -Pn
        #     Skip host discovery.
        #
        # -sT
        #     TCP Connect Scan.
        #
        # -T4
        #     Faster timing.
        #
        # -p 1-1000
        #     Scan TCP ports 1 through 1000.
        #

        arguments = [
            "-Pn",
            "-sT",
            "-T4",
            "-p",
            "1-1000"
        ]

        # ----------------------------------------------------
        # SERVICE DETECTION
        # ----------------------------------------------------

        if service_detection:

            arguments.extend([
                "-sV",
                "--version-light"
            ])

    else:

        raise RuntimeError(
            f"Invalid scan type: {scan_type}. "
            "Use 'quick' or 'standard'."
        )

    # ========================================================
    # XML OUTPUT
    # ========================================================

    arguments.extend([
        "-oX",
        "-"
    ])

    # ========================================================
    # FINAL COMMAND
    # ========================================================

    command = [
        nmap_path,
        *arguments,
        target
    ]

    # ========================================================
    # RUN NMAP
    # ========================================================

    try:

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
            check=False
        )

    except subprocess.TimeoutExpired:

        raise RuntimeError(
            "The scan timed out after "
            f"{SCAN_TIMEOUT} seconds. "
            "Try Quick Scan or disable service detection."
        )

    except OSError as error:

        raise RuntimeError(
            f"Unable to start Nmap: {error}"
        )

    # ========================================================
    # CHECK NMAP ERROR
    # ========================================================

    if process.returncode != 0:

        error_output = (
            process.stderr.strip()
            or process.stdout.strip()
            or "Nmap returned an error."
        )

        raise RuntimeError(
            f"Nmap scan failed: {error_output}"
        )

    # ========================================================
    # CHECK OUTPUT
    # ========================================================

    if not process.stdout.strip():

        raise RuntimeError(
            "Nmap returned no scan results."
        )

    # ========================================================
    # PARSE XML
    # ========================================================

    try:

        root = ET.fromstring(
            process.stdout
        )

    except ET.ParseError as error:

        raise RuntimeError(
            f"Nmap returned invalid XML output: {error}"
        )

    # ========================================================
    # RESULTS
    # ========================================================

    results = []

    for host in root.findall("host"):

        ports_element = host.find("ports")

        if ports_element is None:
            continue

        for port in ports_element.findall("port"):

            # ------------------------------------------------
            # PROTOCOL
            # ------------------------------------------------

            protocol = port.get(
                "protocol",
                ""
            )

            # ------------------------------------------------
            # PORT NUMBER
            # ------------------------------------------------

            port_number = port.get(
                "portid",
                ""
            )

            # ------------------------------------------------
            # STATE
            # ------------------------------------------------

            state_element = port.find("state")

            if state_element is None:
                continue

            state = state_element.get(
                "state",
                ""
            )

            # ------------------------------------------------
            # ONLY RETURN OPEN PORTS
            # ------------------------------------------------

            if state != "open":
                continue

            # ------------------------------------------------
            # SERVICE INFORMATION
            # ------------------------------------------------

            service = ""
            product = ""
            version = ""

            service_element = port.find(
                "service"
            )

            if service_element is not None:

                service = service_element.get(
                    "name",
                    ""
                )

                product = service_element.get(
                    "product",
                    ""
                )

                version = service_element.get(
                    "version",
                    ""
                )

            # ------------------------------------------------
            # CONVERT PORT NUMBER
            # ------------------------------------------------

            try:

                port_number = int(
                    port_number
                )

            except (
                ValueError,
                TypeError
            ):

                continue

            # ------------------------------------------------
            # ADD RESULT
            # ------------------------------------------------

            results.append({

                "port": port_number,

                "protocol": protocol,

                "state": state,

                "service": service,

                "product": product,

                "version": version
            })

    # ========================================================
    # SORT RESULTS
    # ========================================================

    results.sort(
        key=lambda result: (
            result["port"],
            result["protocol"]
        )
    )

    # ========================================================
    # RETURN RESULTS
    # ========================================================

    return results