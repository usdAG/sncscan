#!/usr/bin/env python3.8
# encoding: utf-8
# sncscan - scanner of SNC configurations for routers and SAP systems
#
# Copyright (C) 2023  usd AG
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.
# Author:
#   Jonas Wamsler, Nicolas Schickert from usd AG
#

# Standard imports
import logging
import sys
import traceback
import json
from datetime import datetime
from argparse import ArgumentParser, RawTextHelpFormatter
from binascii import unhexlify as unhex
from socket import error as SocketError
import warnings
# External imports
from scapy.config import conf
# Custom imports
from pysap.SAPDiag import SAPDiagItem, SAPDiag, SAPDiagDP
from pysap.SAPDiagClient import SAPDiagConnection
from pysap.SAPDiagItems import SAPDiagUserConnect, SAPDiagSupportBits
from pysap.SAPRouter import SAPRoutedStreamSocket, SAPRouter, SAPRouterError
from pysap.SAPSNC import SAPSNCFrame, snc_qop, snc_mech_id_values

# Set the verbosity to 0
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
colors = None


class TerminalColors(object):

    def __init__(self, color=True):
        if color:
            self.BLUE = '\033[94m'
            self.CYAN = '\033[96m'
            self.GREEN = '\033[92m'
            self.ORANGE = '\033[93m'
            self.RED = '\033[91m'
            self.END = '\033[0m'
        else:
            self.BLUE = self.CYAN = self.GREEN = self.ORANGE = self.RED = self.END = ""


class SNCScanTarget(object):
    def __init__(self, host, port, route_string, protocol):
        self.host = host
        self.port = port
        self.route_string = route_string
        self.protocol = protocol

    def __str__(self):
        if (self.route_string):
            return f'{self.route_string}'
        else:
            return f'/H/{self.host}/S/{self.port}'


class SNCSecurityScan(object):

    def __init__(self, target):
        self.target = target

    def scan(self):
        if (self.target.protocol == "diag"):
            return self.scan_diag(self.target)
        elif (self.target.protocol == "router"):
            return self.scan_router(self.target)
        else:
            logging.info("Unknown protocol")
            return SNCScanResult(self, "", False, False, "", "", False)

    # sncscan for the SAPROUTER protocol
    def scan_router(self, target):
        logging.info(colors.BLUE + datetime.today().ctime() + colors.END)
        if (target.host):
            logging.info(
                colors.BLUE + 'scanning host: {}'.format(str(target)) + colors.END)
        try:
            # Establish NI connection
            result = SNCScanResult(self, "", False, False, "", "", False)
            conn = SAPRoutedStreamSocket.get_nisocket(target.host,
                                                      target.port,
                                                      target.route_string)

            logging.info(
                colors.BLUE + "connect to server o.k.\n\n" + colors.END)
            # Valid snc token
            snc_token = b"\x30\x82\x00\x61\x06\x06\x2b\x24\x03\x01\x25\x01\xa0\x82\x00\x55" \
                        b"\xa1\x53\x04\x15\x04\x01\x01\x01\x00\x02\x01\x03\x02\x01\x02\x02" \
                        b"\x02\x03\x02\x02\x03\x01\x02\x01\x04\x04\x20\x64\x9d\x49\xe3\x4a" \
                        b"\x7d\xf7\xc8\x79\x0b\x59\x12\x5b\x7d\xc8\xda\xc8\xd7\x79\xa2\xfe" \
                        b"\xd1\xe5\xd7\xaf\x29\x03\x07\x94\x58\x4f\x55\xa1\x18\x30\x0b\x02" \
                        b"\x01\x03\x04\x06\x00\x09\x00\x0a\x00\x0b\x30\x09\x02\x01\x02\x04" \
                        b"\x04\x24\x3b\x9d\x64"

            snc_ext_fields = "\x00\x03\x04\x01\x00\x08\x06\x06\x2b\x24\x03\x01\x25\x01\x00\x00\x00\x19\x30\x17\x31\x15" \
                             "\x30\x13\x06\x03\x55\x04\x03\x13\x0c\x4d\x59\x53\x41\x50\x52\x4f\x55\x54\x45\x52\x32"

            snc_data = "Internal SNC-Adapter (Rev 1.1) to CommonCryptoLib\x00\x00\x00\x00"

            # Creation SNCFrames
            frame_snc = SAPSNCFrame(token=snc_token,
                                    token_length=len(snc_token),
                                    protocol_version=6,
                                    flags=0x7e,  # max protection 0x7e
                                    ext_flags=1,
                                    ext_field_length=len(snc_ext_fields),
                                    ext_fields=snc_ext_fields,
                                    data=snc_data,
                                    data_length=len(snc_data) - 4,
                                    header_length=73
                                    )
            con_text_val = ""
            # Add SNCframe to the SAPROUTER request
            snc_request = SAPRouter(type=SAPRouter.SAPROUTER_CONTROL,
                                    opcode=70,
                                    version=40,
                                    return_code=0,
                                    control_text_value=con_text_val,
                                    control_text_length=len(con_text_val),
                                    snc_frame=frame_snc)
            response = conn.sr(snc_request)

            # Parse response and create output
            response.decode_payload_as(SAPSNCFrame)
            if response[SAPSNCFrame].frame_type == 4:
                result.enabled = True
                result.mechid = snc_mech_id_values.get(
                    response[SAPSNCFrame].mech_id)
                result.qop_flag = response[SAPSNCFrame].flags
                result.cryptolib = response[SAPSNCFrame].data.decode('utf8')
            else:
                result.enabled = False
                response.decode_payload_as(SAPRouter)
                error_information_text = response.err_text_value
                error_information_text.decode_payload_as(SAPRouterError)
                logging.info(
                    colors.RED + error_information_text.error.decode('utf-8') + colors.END)
            result.done = True
            conn.close()
            return result
        except SocketError:
            logging.info(colors.RED + "Connection error" + colors.END)
        except KeyboardInterrupt:
            logging.info("Cancelled by the user")
        return SNCScanResult(self, "", False, False, "", "", False)

    # Initiate snc connection
    def sncinit(self, connection, sncframe):
        connection.connect()
        return connection.sr(SAPDiagDP(rq_id=0, terminal="sncscan") /
                             SAPDiag(com_flag_TERM_INI=1, compress=2, snc_frame=sncframe))

    # Try to connect to the SAPGUI via DIAG

    def check_encrypted_gui(self, connection):
        connection.connect()

        user_connect = SAPDiagItem(item_type=0x10,
                                   item_id=0x04,
                                   item_sid=0x02,
                                   item_value=SAPDiagUserConnect(protocol_version=100200, code_page=1100,
                                                                 ws_type=3000))
        user_connect2 = SAPDiagItem(item_type=0x10,
                                    item_id=0x04,
                                    item_sid=0x0b,
                                    item_value=SAPDiagSupportBits(
                                        unhex(
                                            "ff7ffa0d78b737def6196e9325bf1593ef73feebdb5501000000000000000000")
                                    ))

        return connection.sr(SAPDiagDP(terminal=connection.terminal, rq_id=0) /
                             SAPDiag(compress=0, com_flag_TERM_INI=1) /
                             user_connect /
                             user_connect2)

    # sncscan DIAG protocol
    def scan_diag(self, target):
        """"Implements the niping client running mode

        :param options: option set from the command line
        :type options: Values
        """
        logging.info(colors.BLUE + datetime.today().ctime() + colors.END)
        if (target.host):
            logging.info(
                colors.BLUE + 'scanning host: {} {}'.format(target.host, target.port) + colors.END)
        else:
            logging.info(
                colors.BLUE + 'scanning host: {}'.format(target.route_string) + colors.END)
        try:
            result = SNCScanResult(self, "", False, False, "", "", False)
            # valid snctoken
            snc_token = b"\x30\x82\x00\x61\x06\x06\x2b\x24\x03\x01\x25\x01\xa0\x82\x00\x55" \
                        b"\xa1\x53\x04\x15\x04\x01\x01\x01\x00\x02\x01\x03\x02\x01\x02\x02" \
                        b"\x02\x03\x02\x02\x03\x01\x02\x01\x04\x04\x20\x64\x9d\x49\xe3\x4a" \
                        b"\x7d\xf7\xc8\x79\x0b\x59\x12\x5b\x7d\xc8\xda\xc8\xd7\x79\xa2\xfe" \
                        b"\xd1\xe5\xd7\xaf\x29\x03\x07\x94\x58\x4f\x55\xa1\x18\x30\x0b\x02" \
                        b"\x01\x03\x04\x06\x00\x09\x00\x0a\x00\x0b\x30\x09\x02\x01\x02\x04" \
                        b"\x04\x24\x3b\x9d\x64"

            snc_ext_fields = "\x00\x03\x04\x01\x00\x08\x06\x06\x2b\x24\x03\x01\x25\x01\x00\x00" \
                             "\x00\x10\x30\x0e\x31\x0c\x30\x0a\x06\x03\x55\x04\x03\x13\x03\x4e" \
                             "\x50\x4c"

            snc_data = "Internal SNC-Adapter (Rev 1.1) to CommonCryptoLib\x00\x00\x00\x00"
            # create SNCFrame
            frame_snc = SAPSNCFrame(token=snc_token,
                                    token_length=len(snc_token),
                                    protocol_version=6,
                                    flags=0x2a,  # max protection 0x7e min 0x2a
                                    ext_flags=1,
                                    ext_field_length=len(snc_ext_fields),
                                    ext_fields=snc_ext_fields,
                                    data=snc_data,
                                    data_length=len(snc_data),
                                    header_length=64
                                    )
            # connect with the SAP System
            connection = SAPDiagConnection(target.host, target.port, route=target.route_string,
                                           init=False)
            # initiate SNC connection
            response = self.sncinit(connection, frame_snc)
            logging.info(
                colors.BLUE + "connect to server o.k.\n\n" + colors.END)

            # decode response and parse output
            response.payload.decode_payload_as(SAPSNCFrame)
            if response[SAPSNCFrame].frame_type == 4:
                result.enabled = True
                result.mechid = snc_mech_id_values.get(
                    response[SAPSNCFrame].mech_id)
                result.qop_flag = response[SAPSNCFrame].flags
                result.cryptolib = response[SAPSNCFrame].data.decode('utf8')

                try:
                    # check for only_encrypted_gui flag
                    connection2 = SAPDiagConnection(target.host, target.port, route=target.route_string,
                                                    init=False)
                    response = self.check_encrypted_gui(connection2)
                    result.enforced = response["SAPDiag"].err_no == 1
                except Exception as e:
                    # Need to change after python3, an compression error is thrown but python2 can't handle it.
                    logging.info(traceback.format_exc())

            else:
                response.payload.decode_payload_as(SAPDiag)
                logging.info(
                    colors.RED + 'Error: {}'.format(response[SAPDiag].info) + colors.END)
                if 'Security Network Layer (SNC) error' in response[SAPDiag].info:
                    result.enabled = False
            result.done = True
            return result

        except SocketError:
            logging.info(colors.RED + "Connection error" + colors.END)
        except KeyboardInterrupt:
            logging.info("[*] Cancelled by the user")
        return SNCScanResult(self, "", False, False, "", "", False)


class SNCScanResult(object):
    def __init__(self, scan, qop_flag, enabled, enforced, mechid, cryptolib, done):
        self.scan = scan
        self.qop_flag = int(qop_flag) if qop_flag != "" else 0
        self.qop_use, self.qop_max, self.qop_min = self.parse_qop()
        self.enabled = enabled
        self.enforced = enforced
        self.mechid = mechid
        self.cryptolib = cryptolib
        self.done = done

    def parse_qop(self):
        return (self.qop_flag & 0b1100000) >> 5, (self.qop_flag & 0b0011000) >> 3, (self.qop_flag & 0b0000110) >> 1
        try:
            return (self.qop_flag & 0b1100000) >> 5, (self.qop_flag & 0b0011000) >> 3, (self.qop_flag & 0b0000110) >> 1
        except:
            return 0, 0, 0

    def format_json(self):
        if (self.scan.target.protocol == "router"):
            return json.dumps({"target": str(self.scan.target), "qop_use": self.qop_use, "qop_max": self.qop_max, "qop_min": self.qop_min, "enabled": self.enabled, "mechid": self.mechid, "cryptolib": self.cryptolib, "done": self.done})
        else:
            return json.dumps({"target": str(self.scan.target), "qop_use": self.qop_use, "qop_max": self.qop_max, "qop_min": self.qop_min, "enabled": self.enabled, "enforced": self.enforced, "mechid": self.mechid, "cryptolib": self.cryptolib, "done": self.done})

    def format_only_violations(self):
        if not self.enabled:
            output = f"Target: {self.scan.target}\n"
            output += f"SNC enabled system (snc/enabled): {colors.RED}{int(self.enabled)} (no){colors.END}\n"
        else:
            output = f"Target: {self.scan.target}\n"
            if (self.qop_flag != 0x7e):
                output += f"Flag: {colors.RED+hex(self.qop_flag)+colors.END}\n"
            output += "Quality of Protection\n"
            for parameter, value in [("use", self.qop_use), ("max", self.qop_max), ("min", self.qop_min)]:
                if (value != 3):
                    output += f"\tsnc/data_protection/{parameter}\t{colors.RED}{value} ({snc_qop.get(value)}){colors.END}\n"
            if self.scan.target.protocol == "diag" and not self.enforced:
                output += f"\nUnencrypted communication is allowed by this system:\n"
                output += f"snc/only_encrypted_gui\t{colors.RED}0 (False){colors.END}\n"
        return output

    def format_pretty(self):
        if not self.enabled:
            output = f"Target: {self.scan.target}\n"
            output += f"SNC enabled system (snc/enabled): {colors.RED}{int(self.enabled)} (no){colors.END}\n"
        else:
            output = f"Target: {self.scan.target}\n"
            output += f"SNC enabled system (snc/enabled): {colors.GREEN}{int(self.enabled)} (yes){colors.END}\n"
            output += f"MechID: {self.mechid}\n"
            output += f"Used Cryptolib: {self.cryptolib}\n"
            if (self.qop_flag == 0x7e):
                output += f"Flag: {colors.GREEN+hex(self.qop_flag)+colors.END}\n"
            else:
                output += f"Flag: {colors.RED+hex(self.qop_flag)+colors.END}\n"
            output += "Quality of Protection\n"
            for parameter, value in [("use", self.qop_use), ("max", self.qop_max), ("min", self.qop_min)]:
                output += f"\tsnc/data_protection/{parameter}\t{colors.GREEN if value == 3 else colors.RED}{value} ({snc_qop.get(value)}){colors.END}\n"

            if self.scan.target.protocol == "diag":
                output += f"\nUnencrypted communication is {'not' if self.enforced else ''} allowed by this system:\n"
                output += f"snc/only_encrypted_gui\t{colors.GREEN if self.enforced else colors.RED}{'1' if self.enforced else '0'} ({self.enforced}){colors.END}\n"
        return output

    def output(self, format):
        if not self.done:
            print(f"Target:{str(self.scan.target)} - scan unsuccessful.")
            return
        self.qop_use, self.qop_max, self.qop_min = self.parse_qop()
        if (format == "pretty"):
            print(self.format_pretty())
        elif (format == "plain"):
            if (self.scan.target.protocol == "router"):
                print(
                    f"Target:{str(self.scan.target)} QoP:{hex(self.qop_flag)} Enabled:{self.enabled} MechID:{self.mechid} CryptoLib:{self.cryptolib} Done:{self.done}")
            else:
                print(f"Target:{str(self.scan.target)} QoP:{hex(self.qop_flag)} Enabled:{self.enabled} Enforced:{self.enforced} MechID:{self.mechid} CryptoLib:{self.cryptolib} Done:{self.done}")
        elif (format == "json"):
            print(self.format_json())
        elif (format == "only_violations"):
            print(self.format_only_violations())

# Command line options parser


def parse_options():
    global colors
    colors = TerminalColors(True)

    description = f'{ascii_art()}\nSAP Secure Network Communication analysis tool developed by usd AG {colors.ORANGE}\u25e5{colors.END} \nBased on the pysap library by Martin Gallo.'

    usage = "%(prog)s -H <remote host> [-S <Port>] -p <diag|router> [-o <file>] [-v][-q][--no-color][-f <format]"
    usage += "\n\t%(prog)s --route-string </H/S/H/S/> -p <diag|router> [-o <file>] [-v][-q][--no-color][-f <format]"
    usage += "\n\t%(prog)s -L <list of hosts>|-iL <list of hosts in file> [-o <file>] [-v][-q][--no-color][-f <format]"

    parser = ArgumentParser(
        usage=usage, description=description, formatter_class=RawTextHelpFormatter)

    target = parser.add_argument_group("Target")
    target.add_argument("-H", "--host", dest="host", help="Host")
    target.add_argument("-S", "--port", dest="port", type=int, default=3299,
                        help="Port [%(default)d]")
    target.add_argument("--route-string", dest="route_string",
                        help="Format: /H/first-IP/S/Port/H/second-IP/S/Port")
    misc = parser.add_argument_group("Misc options")
    misc.add_argument("-v", "--verbose", dest="verbose",
                      action="store_true", help="Verbose output")
    misc.add_argument("-p", "--protocol", dest="protocol",
                      help="Protocol (diag/router)")
    misc.add_argument("-o", "--output", dest="file_output",
                      help="Print output to text file")
    misc.add_argument("-f", "--format", dest="format",
                      default="pretty", help="Format for output")
    misc.add_argument("-L", "--list", dest="list",
                      help="List of multiple DIAG targets, in routestring format and comma seperated")
    misc.add_argument("-iL", "--listfile", dest="listfile",
                      help="List of multiple DIAG targets, in routestring format and comma seperated, stored in a file")
    misc.add_argument("--no-color", dest="color",
                      action="store_false", help="Disable colors in output.")
    misc.add_argument("-q", dest="quiet", action="store_true",
                      help="Disable scan status information output.")

    options = parser.parse_args()

    colors = TerminalColors(options.color and not options.file_output)

    if not (options.host or options.route_string or options.list or options.listfile):
        parser.print_help()
        sys.exit()

    return options


def ascii_art():
    return colors.CYAN + ' ___ _ __   ___ ___  ___ __ _ _ __\n' \
        '/ __| \'_ \ / __/ __|/ __/ _` | \'_ \ \n' \
        '\__ \ | | | (__\__ \ (_| (_| | | | |\n' \
        '|___/_| |_|\___|___/\___\__,_|_| |_|\n' + colors.END \


# Main function


def main():
    options = parse_options()

    if not options.quiet:
        print(ascii_art())

    level = logging.INFO
    if options.quiet:
        level = logging.WARNING
    if options.verbose:
        level = logging.DEBUG
    if options.file_output:
        stdoutOrigin = sys.stdout
        sys.stdout = open(options.file_output, "w")
    logging.basicConfig(level=level, format='%(message)s')
    if options.list or options.listfile:
        targetlist = ""
        if options.listfile:
            with open(options.listfile, "r") as file:
                targetlist = file.read().replace("\n", ",")
                targetlist = targetlist[:-1] if targetlist[-1] == ',' else targetlist
        else:
            targetlist = options.list
        for target in targetlist.split(","):
            if (options.format == "pretty"):
                print(70*"-")
            if (len(target.split("H")) > 2):
                result = SNCSecurityScan(SNCScanTarget(
                    None, None, target, "diag")).scan()
                result.output(options.format)
            else:
                host = target.split("/")[2]
                port = target.split("/")[4]
                result = SNCSecurityScan(SNCScanTarget(
                    host, port, None, "diag")).scan()
                result.output(options.format)
    else:
        result = SNCSecurityScan(SNCScanTarget(
            options.host, options.port, options.route_string, options.protocol)).scan()
        result.output(options.format)


if __name__ == "__main__":
    main()
