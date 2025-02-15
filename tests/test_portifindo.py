import unittest
from unittest.mock import patch, MagicMock
from portifindo import *


class PortifindoTest(unittest.TestCase):

    def test_validateIP(self):
        self.assertTrue(validateIP("192.168.1.1"))
        self.assertFalse(validateIP("999.999.999.999"))
        self.assertFalse(validateIP("invalid_ip"))

    def test_validatePorts(self):
        self.assertTrue(validatePorts("80"))
        self.assertTrue(validatePorts("80,443"))
        self.assertFalse(validatePorts("abc,443"))
        self.assertFalse(validatePorts("80,abc"))

    @patch("socket.socket")
    def test_bannerGrabbing(self, mock_socket):
        # Mock socket behavior
        mock_socket.return_value.recv.return_value = b"Server: Apache"
        banner = bannerGrabbing("192.168.1.1", 80)
        self.assertEqual(banner, "Apache")

    @patch("socket.getservbyport")
    def test_detectService(self, mock_getservbyport):
        mock_getservbyport.return_value = "http"
        service = detectService("192.168.1.2", 80)
        self.assertEqual(service, "http")


def main():
    unittest.main()


if __name__ == "__main__":
    main()
