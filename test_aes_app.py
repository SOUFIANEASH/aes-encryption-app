import unittest
from unittest import mock
import sys

import aes_app


class Crypto(unittest.TestCase):
    def test_roundtrip_all(self):
        for mode in ("ECB", "CBC", "CFB"):
            for bits in (128, 192, 256):
                for text in ("a", "Hello AES ✓", "x" * 16, "y" * 100):
                    ct = aes_app.encrypt(text, "secret", mode, bits)
                    self.assertEqual(aes_app.decrypt(ct, "secret", mode, bits), text)

    def test_key_sizes(self):
        for bits in (128, 192, 256):
            self.assertEqual(len(aes_app.make_key("pw", bits)), bits // 8)

    def test_empty_key(self):
        with self.assertRaises(ValueError):
            aes_app.encrypt("hi", "", "CBC", 128)

    def test_wrong_key(self):
        for mode in ("ECB", "CBC", "CFB"):
            ct = aes_app.encrypt("secret text here", "right", mode, 128)
            try:
                self.assertNotEqual(aes_app.decrypt(ct, "wrong", mode, 128), "secret text here")
            except ValueError:
                pass

    def test_modes_differ(self):
        self.assertNotEqual(aes_app.encrypt("same", "k", "CBC", 128), aes_app.encrypt("same", "k", "CBC", 128))


class GuiSmoke(unittest.TestCase):
    """Runs main() against a fake tkinter to catch typos/NameErrors in the GUI code."""
    def test_main_runs_and_buttons_work(self):
        fake = mock.MagicMock()
        values = {}

        class Var:
            def __init__(self, value=""): self.v = value
            def get(self): return self.v
            def set(self, v): self.v = v
        fake.tk.StringVar = Var
        texts = []

        class Text:
            def __init__(self, *a, **k): self.s = ""; texts.append(self)
            def pack(self, *a, **k): pass
            def get(self, *a): return self.s + "\n"
            def delete(self, *a): self.s = ""
            def insert(self, i, s): self.s = s
        fake.tk.Text = Text
        buttons = {}
        def Button(parent, text=None, command=None, **k):
            buttons[text] = command
            return mock.MagicMock()
        fake.tk.Button = Button
        entry_vars = {}
        def Entry(parent, textvariable=None, **k):
            entry_vars["key"] = textvariable
            return mock.MagicMock()
        fake.tk.Entry = Entry
        mods = {"tkinter": fake.tk, "tkinter.filedialog": fake.filedialog,
                "tkinter.messagebox": fake.messagebox, "tkinter.ttk": fake.ttk}
        fake.tk.filedialog = fake.filedialog
        fake.tk.messagebox = fake.messagebox
        fake.tk.ttk = fake.ttk
        with mock.patch.dict(sys.modules, mods):
            aes_app.main()
        inp, out = texts
        entry_vars["key"].set("pw")
        inp.s = "hello gui"
        buttons["Run"]()
        self.assertTrue(out.s)
        ciphertext = out.s
        inp.s = ciphertext
        # switch operation to Decrypt via load-file path
        fake.filedialog.askopenfilename.return_value = ""
        buttons["Load .txt into input"]()
        # operation unchanged (no file chosen) -> still Encrypt, so just check no crash
        fake.messagebox.showerror.assert_not_called()


if __name__ == "__main__":
    unittest.main()
