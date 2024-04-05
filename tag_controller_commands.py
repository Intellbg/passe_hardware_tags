import socket
import logging
from sys import argv
import argparse

import logging
from logging.handlers import TimedRotatingFileHandler
import os

log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
logging.basicConfig(level=logging.DEBUG)
handler = TimedRotatingFileHandler(
    os.path.join(log_dir, "tags.log"), when="midnight", interval=1, backupCount=7
)
handler.suffix = "%Y-%m-%d"
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logging.getLogger("").addHandler(handler)

debug = False


def _set_tag_number(data, tag_number):
    bytes_cardNo = tag_number.to_bytes(4, "big")
    data[8] = bytes_cardNo[3]
    data[9] = bytes_cardNo[2]
    data[10] = bytes_cardNo[1]
    data[11] = bytes_cardNo[0]
    return data


def _set_date(data):
    data[12] = 0x20
    data[13] = 0x10
    data[14] = 0x01
    data[15] = 0x01
    data[16] = 0x20
    data[17] = 0x29
    data[18] = 0x01
    data[19] = 0x01
    return data


def _set_tag_permissions(data, door_1=0x01, door_2=0x01, door_3=0x01, door_4=0x01):
    data[20] = door_1
    data[21] = door_2
    data[22] = door_3
    data[23] = door_4
    return data


def _set_sn(data, sn):
    bytes_sn = sn.to_bytes(4, "big")
    data[4] = bytes_sn[3]
    data[5] = bytes_sn[2]
    data[6] = bytes_sn[1]
    data[7] = bytes_sn[0]
    return data


def _add_update_tag(
    tag_number, ip, sn, port=6000, door_1=0x01, door_2=0x01, door_3=0x01, door_4=0x01
):
    data = [0x00] * 64
    data[0] = 0x17
    data[1] = 0x50  # command
    data = _set_sn(data, sn)
    data = _set_tag_number(data, tag_number)
    data = _set_date(data)
    data = _set_tag_permissions(data, door_1, door_2, door_3, door_4)
    data[40] = 0x02
    byte_array = send_request(data, (ip, port))


def retrieve_tag(tag_number: str, ip: str, sn: str, port=60000):
    data = [0x00] * 64
    data[0] = 0x17
    data[1] = 0x5A  # command
    data = _set_sn(data, sn)
    data = _set_tag_number(data, tag_number)
    data[40] = 0x01
    byte_array = send_request(data, (ip, port))
    if not byte_array:
        logging.error("Could not retrieve")
        return
    logging.info(
        f"Permisos: 1-{byte_array[20]} 2-{byte_array[21]} 3-{byte_array[22]} 4-{byte_array[23]}"
    )


def delete_tag(tag_number: str, ip: str, sn: str, port=60000):
    data = [0x00] * 64
    data[0] = 0x17
    data[1] = 0x52  # command
    data = _set_sn(data, sn)
    data = _set_tag_number(data, tag_number)
    data[40] = 0x01
    byte_array = send_request(data, (ip, port))
    if not byte_array:
        logging.error("Could not retrieve")
        return
    logging.info(f"Deleted {tag_number}")


def create_tag(tag_number: str, ip: str, sn: int, port=60000):
    _add_update_tag(tag_number, ip, sn, port)
    logging.info(f"Tag {tag_number} created")


def allow_tag(tag_number: str, ip: str, sn: int, port=60000):
    _add_update_tag(tag_number, ip, sn, port)
    logging.info(f"Tag {tag_number} allowed")


def block_tag(tag_number: str, ip: str, sn: int, port=60000):
    _add_update_tag(
        tag_number, ip, sn, port, door_1=0x00, door_2=0x00, door_3=0x00, door_4=0x00
    )
    logging.info(f"Tag {tag_number} blocked")


def config_server_ip():
    return None


def retrieve_server_ip(ip, sn, port=6000):
    data = [0x00] * 64
    data[0] = 0x17
    data[1] = 0x92  # command
    data = _set_sn(data, sn)
    data[40] = 0x01
    byte_array = send_request(data, (ip, port))
    if not byte_array:
        logging.error("Could not retrieve")
    logging.info(f"IP: {byte_array[8]}.{byte_array[9]}.{byte_array[10]}.{byte_array[11]}, PORT: {int.from_bytes(byte_array[12:14])}, TIME:{byte_array[14]}")

def send_request(data, address):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(5)
    try:
        client_socket.connect(address)
        client_socket.sendall(bytearray(data))
        response, server2 = client_socket.recvfrom(64)
        return bytearray(response)
    except socket.timeout:
        logging.error("Timeout: Unable to receive a response within 5 seconds.")
    except Exception as e:
        logging.error(e)
    finally:
        client_socket.close()
    return []


def main(ip, sn, command, tag=None, port=60000, server_ip=None):
    sn = int(sn)
    if command in ["create", "allow", "bloc", "retrieve"] and not tag:
        logging.error("Tag number needed")
        return
    if tag:
        tag = int(tag)
    if command in ["config_server"] and not server_ip:
        logging.error("Server IP needed")
        return
    if command == "create":
        create_tag(tag, ip, sn, port)
        return
    elif command == "allow":
        allow_tag(tag, ip, sn, port)
        return
    elif command == "block":
        block_tag(tag, ip, sn, port)
        return
    elif command == "retrieve":
        retrieve_tag(tag, ip, sn, port)
        return
    elif command == "delete":
        delete_tag(tag, ip, sn, port)
        return
    elif command == "retrieve_server_ip":
        retrieve_server_ip(ip, sn, port)
        return
    logging.error("Wrong command")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Passe Tag Controller")
    parser.add_argument("ip", help="Controller IP")
    parser.add_argument("sn", help="Controller SN")
    parser.add_argument("command", help="Controller Command")
    parser.add_argument("-t", "--tag", help="Tag Number")
    parser.add_argument("-i", "--server", help="Auxiliar server IP")
    parser.add_argument("-P", "--port", default=60000, help="Connection port")
    parser.add_argument("-D", "--debug", help="Enable debug")
    args = parser.parse_args()

    main(args.ip, args.sn, args.command, args.tag, args.port, args.server)
