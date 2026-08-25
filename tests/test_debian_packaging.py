import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class DebianPackagingTests(unittest.TestCase):
    def test_postinst_does_not_contact_sensor_or_modify_auth_stack(self):
        postinst = (ROOT / 'debian/python3-validity.postinst').read_text()

        self.assertNotIn('udevadm trigger', postinst)
        self.assertNotIn('pam-auth-update', postinst)
        self.assertIn('udevadm control --reload-rules', postinst)

    def test_dpkg_does_not_start_driver_mid_transaction(self):
        rules = (ROOT / 'debian/rules').read_text()

        self.assertIn(
            'dh_installsystemd --name=python3-validity --no-start',
            rules,
        )

    def test_matched_hardware_still_starts_without_manual_configuration(self):
        rules = (ROOT / 'debian/python3-validity.udev').read_text()

        self.assertIn('ACTION=="add|change"', rules)
        self.assertIn('start python3-validity.service', rules)
        self.assertIn('LABEL="python_validity_match"', rules)


if __name__ == '__main__':
    unittest.main()
