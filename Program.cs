using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace UsbStorageGuardManager
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new LoginForm());
        }
    }

    // ===== صيغة كلمة المرور: magic(4)+ver(1)+iter(4)+saltLen(1)+salt+hashLen(1)+hash =====
    static class Vault
    {
        static readonly byte[] Magic = { (byte)'U', (byte)'S', (byte)'G', (byte)'P' };
        const byte Version = 1;
        public const int Iterations = 200_000;

        public static string Path => System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "USBStorageGuardAdvanced", "password.dat");

        public static bool Exists => File.Exists(Path);

        public static void Save(string password)
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
            using var ms = new MemoryStream();
            ms.Write(Magic); ms.WriteByte(Version);
            ms.Write(BitConverter.GetBytes(Iterations));
            ms.WriteByte((byte)salt.Length); ms.Write(salt);
            ms.WriteByte((byte)hash.Length); ms.Write(hash);
            string tmp = Path + ".tmp";
            File.WriteAllBytes(tmp, ms.ToArray());
            File.Move(tmp, Path, overwrite: true);
        }

        public static bool Verify(string password)
        {
            if (!File.Exists(Path)) return false;
            try
            {
                var b = File.ReadAllBytes(Path);
                if (b.Length < 10 || !b.AsSpan(0, 4).SequenceEqual(Magic)) return false;
                if (b[4] != Version) return false;
                int iter = BitConverter.ToInt32(b, 5);
                int sl = b[9]; var salt = b.AsSpan(10, sl).ToArray();
                int hl = b[10 + sl]; var hash = b.AsSpan(11 + sl, hl).ToArray();
                var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iter, HashAlgorithmName.SHA256, hl);
                return CryptographicOperations.FixedTimeEquals(actual, hash);
            }
            catch { return false; }
        }
    }

    class LoginForm : Form
    {
        public LoginForm()
        {
            RightToLeft = RightToLeft.Yes; RightToLeftLayout = true;
            Text = "USB Storage Guard — تسجيل الدخول";
            Width = 420; Height = 230; FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            var lbl = new Label { Text = "كلمة المرور:", Left = 26, Top = 30, AutoSize = true };
            var pwd = new TextBox { Left = 26, Top = 60, Width = 340, UseSystemPasswordChar = true };
            var ok  = new Button { Text = "دخول", Left = 26, Top = 100, Width = 160 };
            var newBtn = new Button { Text = "إنشاء كلمة مرور", Left = 206, Top = 100, Width = 160 };
            var msg = new Label { Left = 26, Top = 145, Width = 360, AutoSize = false, Height = 40 };
            AcceptButton = ok;

            ok.Click += (_, __) =>
            {
                if (!Vault.Exists) { msg.Text = "لا توجد كلمة مرور محفوظة. أنشئ واحدة أولاً."; return; }
                if (Vault.Verify(pwd.Text)) { Hide(); new MainForm().ShowDialog(); Close(); }
                else msg.Text = "كلمة المرور غير صحيحة.";
            };
            newBtn.Click += (_, __) =>
            {
                if (pwd.Text.Length < 8) { msg.Text = "8 أحرف على الأقل."; return; }
                if (Vault.Exists && MessageBox.Show("استبدال كلمة المرور الحالية؟", "تأكيد",
                    MessageBoxButtons.YesNo) != DialogResult.Yes) return;
                try { Vault.Save(pwd.Text); msg.Text = "تم الحفظ."; pwd.Clear(); }
                catch (Exception ex) { msg.Text = "فشل: " + ex.Message; }
            };

            Controls.AddRange(new Control[] { lbl, pwd, ok, newBtn, msg });
        }
    }

    class MainForm : Form
    {
        const ulong DefaultLimit = 265_000_000_000UL;
        NumericUpDown gb = new NumericUpDown { Left = 26, Top = 60, Width = 200,
            Maximum = 100_000, Minimum = 1, Value = 265 };
        CheckBox enabled = new CheckBox { Text = "تفعيل الحظر", Left = 26, Top = 95, AutoSize = true };
        Label status = new Label { Left = 26, Top = 160, Width = 440, Height = 60 };

        public MainForm()
        {
            RightToLeft = RightToLeft.Yes; RightToLeftLayout = true;
            Text = "USB Storage Guard Advanced"; Width = 520; Height = 300;
            FormBorderStyle = FormBorderStyle.FixedDialog; MaximizeBox = false;
            var lbl = new Label { Text = "الحد الأقصى (GB):", Left = 26, Top = 30, AutoSize = true };
            var save = new Button { Text = "حفظ السياسة", Left = 246, Top = 58, Width = 220 };
            save.Click += (_, __) => SavePolicy();
            var refresh = new Button { Text = "تحديث الحالة", Left = 246, Top = 93, Width = 220 };
            refresh.Click += (_, __) => RefreshState();
            Controls.AddRange(new Control[] { lbl, gb, enabled, save, refresh, status });
            RefreshState();
        }

        void SavePolicy() => CallService(new
        {
            Op = "set",
            Enabled = enabled.Checked ? 1u : 0u,
            MaxBytes = (ulong)gb.Value * 1_000_000_000UL
        });

        void RefreshState()
        {
            var r = CallService(new { Op = "get", Enabled = 0u, MaxBytes = 0UL });
            if (r.StartsWith("{\"error\"")) { status.Text = "الخدمة غير متاحة: " + r; return; }
            var p = JsonSerializer.Deserialize<PolicyDto>(r);
            enabled.Checked = p.Enabled == 1;
            gb.Value = Math.Max(1, p.MaxBytes / 1_000_000_000UL);
            status.Text = $"السياسة الحالية: {(p.Enabled == 1 ? "مفعّلة" : "معطّلة")} — الحد {gb.Value} GB";
        }

        static string CallService(object req)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", "UsbStorageGuard.pipe", PipeDirection.InOut);
                pipe.Connect(3000);
                using var w = new StreamWriter(pipe, Encoding.UTF8) { AutoFlush = true };
                using var r = new StreamReader(pipe, Encoding.UTF8);
                w.WriteLine(JsonSerializer.Serialize(req));
                return r.ReadLine() ?? "{\"error\":-1}";
            }
            catch (Exception ex) { return $"{{\"error\":{ex.HResult}}}"; }
        }
        record PolicyDto(uint Enabled, ulong MaxBytes);
    }
}
