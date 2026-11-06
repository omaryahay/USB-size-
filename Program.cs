using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Windows.Forms;

namespace UsbStorageGuardManager
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }

    public class MainForm : Form
    {
        const string AppDirName = "USBStorageGuardAdvanced";
        string SettingsPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            AppDirName, "password.dat");

        TextBox password = new TextBox { UseSystemPasswordChar = true, Width = 220 };
        Label status = new Label { AutoSize = true, Text = "الحماية غير مفعّلة في هذه النسخة التأسيسية." };

        public MainForm()
        {
            Text = "USB Storage Guard Advanced";
            Width = 520; Height = 300;
            BackColor = System.Drawing.Color.FromArgb(238, 248, 240);
            var title = new Label { Text = "USB Storage Guard Advanced", AutoSize = true,
                Font = new System.Drawing.Font("Segoe UI", 16, System.Drawing.FontStyle.Bold),
                Left = 24, Top = 20 };
            var info = new Label { Text = "الحد الأقصى المبدئي: 265 GB", AutoSize = true, Left = 26, Top = 72 };
            password.Left = 26; password.Top = 112;
            var save = new Button { Text = "إنشاء / تغيير كلمة المرور", Left = 26, Top = 154, Width = 220 };
            save.Click += (s, e) => SavePassword();
            status.Left = 26; status.Top = 198;
            var credit = new Label { Text = "عمر يحي سيلان", AutoSize = true, Left = 26, Top = 232,
                ForeColor = System.Drawing.Color.DarkGreen };
            Controls.AddRange(new Control[] { title, info, password, save, status, credit });
        }

        void SavePassword()
        {
            if (password.Text.Length < 8) {
                MessageBox.Show("اجعل كلمة المرور 8 أحرف على الأقل.");
                return;
            }
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath));
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            using (var derive = new Rfc2898DeriveBytes(password.Text, salt, 200000, HashAlgorithmName.SHA256)) {
                byte[] hash = derive.GetBytes(32);
                File.WriteAllBytes(SettingsPath, salt.Concat(hash).ToArray());
            }
            password.Clear();
            status.Text = "تم حفظ مشتق كلمة المرور محلياً.";
        }
    }
}
