import unittest
from parsing import *
#before runnning the tests, run the EPC

class ParsingTesting(unittest.TestCase):
    def test_checkIE_accepted_1(self):
        mand = [(42, 'ok')]
        opt = [(24,'not ok')]
        input = [{"id": 42, "criticality":"ok"}]
        self.assertTrue(parsing.checkIE_accepted(input,mand,opt))
    def test_checkIE_accepted_2(self):
        mand = [(42, 'ok')]
        opt = [(24,'not ok')]
        input = [{"id": 42, "criticality":"ok"},{"id":24,"criticality":"not ok"}]
        self.assertTrue(parsing.checkIE_accepted(input,mand,opt))
    def test_checkIE_accepted_3(self):
        mand = [(42, 'ok'), (43,'excelent')]
        opt = [(24,'not ok')]
        input = [{"id": 42, "criticality":"ok"},{"id":24,"criticality":"not ok"}]
        self.assertFalse(parsing.checkIE_accepted(input,mand,opt))
    def test_checkIE_accepted_4(self):
        mand = [(42, 'ok'), (43,'excelent')]
        opt = [(24,'not ok')]
        input = [{"id": 42, "criticality":"ok"}]
        self.assertFalse(parsing.checkIE_accepted(input,mand,opt))
    def test_checkIE_accepted_5(self):
        mand = [(42, 'ok'), (43,'excelent')]
        opt = [(24,'not ok')]
        input = []
        self.assertFalse(parsing.checkIE_accepted(input,mand,opt))
    def test_checkIE_accepted_6(self):
        mand = []
        opt = [(24,'not ok')]
        input = [{"id": 42, "criticality":"ok"}]
        self.assertFalse(parsing.checkIE_accepted(input,mand,opt))
    def test_checkIE_accepted_7(self):
        mand = []
        opt = [(24,'not ok')]
        input = [{"id": 24, "criticality":"not ok"}]
        self.assertTrue(parsing.checkIE_accepted(input,mand,opt))