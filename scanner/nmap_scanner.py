import subprocess
import shutil
import xml.etree.ElementTree as ET


# ============================================================
# NMAP CONFIGURATION
# ============================================================

SCAN_TIMEOUT = 150


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

    Returns a list of dictionaries containing:
        port
        protocol
        state
        service
        product
        version
    """

    # --------------------------------------------------------
    # FIND NMAP
    # --------------------------------------------------------

    nmap_path = shutil.which("nmap")

    if not nmap_path:

        raise RuntimeError(
            "Nmap is not installed or is not available in PATH."
        )

    # --------------------------------------------------------
    # SCAN TYPE
    # --------------------------------------------------------

    if scan_type == "quick":

        arguments = [
            "-T4",
            "-F"
        ]

    else:

        arguments = [
            "-T4",
            "-p-"
        ]

    # --------------------------------------------------------
    # SERVICE DETECTION
    # --------------------------------------------------------

    if service_detection:

        arguments.append("-sV")

    # --------------------------------------------------------
    # XML OUTPUT
    # --------------------------------------------------------

    arguments.extend([
        "-oX",
        "-"
    ])

    # --------------------------------------------------------
    # BUILD COMMAND
    # --------------------------------------------------------

    command = [
        nmap_path,
        *arguments,
        target
    ]

    # --------------------------------------------------------
    # RUN NMAP
    # --------------------------------------------------------

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
            "The scan timed out. "
            "Try using Quick Scan or another authorized target."
        )

    except OSError as error:

        raise RuntimeError(
            f"Unable to start Nmap: {error}"
        )

    # --------------------------------------------------------
    # NMAP ERROR
    # --------------------------------------------------------

    if process.returncode != 0:

        error_output = (
            process.stderr.strip()
            or "Nmap returned an error."
        )

        raise RuntimeError(
            error_output
        )

    # --------------------------------------------------------
    # PARSE XML
    # --------------------------------------------------------

    try:

        root = ET.fromstring(
            process.stdout
        )

    except ET.ParseError:

        raise RuntimeError(
            "Nmap returned an invalid scan result."
        )

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    results = []

    for host in root.findall("host"):

        ports_element = host.find("ports")

        if ports_element is None:
            continue

        for port in ports_element.findall("port"):

            protocol = port.get(
                "protocol",
                ""
            )

            port_number = port.get(
                "portid",
                ""
            )

            state_element = port.find("state")

            if state_element is None:
                continue

            state = state_element.get(
                "state",
                ""
            )

            # Only return ports that are actually open.
            if state != "open":
                continue

            service_element = port.find("service")

            service = ""
            product = ""
            version = ""

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

            try:

                port_number = int(
                    port_number
                )

            except ValueError:

                continue

            results.append({

                "port": port_number,

                "protocol": protocol,

                "state": state,

                "service": service,

                "product": product,

                "version": version
            })

    # --------------------------------------------------------
    # SORT RESULTS
    # --------------------------------------------------------

    results.sort(
        key=lambda result: (
            result["port"],
            result["protocol"]
        )
    )

    return results