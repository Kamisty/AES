namespace AESAnalyzer
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            radio128 = new RadioButton();
            radio192 = new RadioButton();
            radio256 = new RadioButton();
            tabControl1 = new TabControl();
            tabPage1 = new TabPage();
            lavina = new TextBox();
            button4 = new Button();
            IV = new TextBox();
            label5 = new Label();
            text2 = new TextBox();
            button3 = new Button();
            textBox1 = new TextBox();
            label4 = new Label();
            label3 = new Label();
            key2 = new TextBox();
            key = new TextBox();
            label2 = new Label();
            text = new TextBox();
            button2 = new Button();
            label1 = new Label();
            button1 = new Button();
            tabPage4 = new TabPage();
            proisv = new TextBox();
            button5 = new Button();
            label6 = new Label();
            tabControl1.SuspendLayout();
            tabPage1.SuspendLayout();
            tabPage4.SuspendLayout();
            SuspendLayout();
            // 
            // radio128
            // 
            radio128.AutoSize = true;
            radio128.Checked = true;
            radio128.Location = new Point(232, 320);
            radio128.Name = "radio128";
            radio128.Size = new Size(99, 29);
            radio128.TabIndex = 0;
            radio128.TabStop = true;
            radio128.Text = "128 бит";
            radio128.UseVisualStyleBackColor = true;
            radio128.CheckedChanged += radioButton1_CheckedChanged;
            // 
            // radio192
            // 
            radio192.AutoSize = true;
            radio192.Location = new Point(232, 371);
            radio192.Name = "radio192";
            radio192.Size = new Size(99, 29);
            radio192.TabIndex = 1;
            radio192.Text = "192 бит";
            radio192.UseVisualStyleBackColor = true;
            radio192.CheckedChanged += radioButton2_CheckedChanged;
            // 
            // radio256
            // 
            radio256.AutoSize = true;
            radio256.Location = new Point(232, 415);
            radio256.Name = "radio256";
            radio256.Size = new Size(99, 29);
            radio256.TabIndex = 2;
            radio256.Text = "256 бит";
            radio256.UseVisualStyleBackColor = true;
            // 
            // tabControl1
            // 
            tabControl1.Controls.Add(tabPage1);
            tabControl1.Controls.Add(tabPage4);
            tabControl1.Location = new Point(30, 22);
            tabControl1.Name = "tabControl1";
            tabControl1.SelectedIndex = 0;
            tabControl1.Size = new Size(1791, 1138);
            tabControl1.TabIndex = 3;
            // 
            // tabPage1
            // 
            tabPage1.Controls.Add(label6);
            tabPage1.Controls.Add(lavina);
            tabPage1.Controls.Add(button4);
            tabPage1.Controls.Add(IV);
            tabPage1.Controls.Add(label5);
            tabPage1.Controls.Add(text2);
            tabPage1.Controls.Add(button3);
            tabPage1.Controls.Add(textBox1);
            tabPage1.Controls.Add(label4);
            tabPage1.Controls.Add(label3);
            tabPage1.Controls.Add(key2);
            tabPage1.Controls.Add(key);
            tabPage1.Controls.Add(label2);
            tabPage1.Controls.Add(text);
            tabPage1.Controls.Add(button2);
            tabPage1.Controls.Add(label1);
            tabPage1.Controls.Add(button1);
            tabPage1.Controls.Add(radio256);
            tabPage1.Controls.Add(radio192);
            tabPage1.Controls.Add(radio128);
            tabPage1.Location = new Point(4, 34);
            tabPage1.Name = "tabPage1";
            tabPage1.Padding = new Padding(3);
            tabPage1.Size = new Size(1783, 1100);
            tabPage1.TabIndex = 0;
            tabPage1.Text = "Шифрование AES";
            tabPage1.UseVisualStyleBackColor = true;
            tabPage1.Click += tabPage1_Click;
            // 
            // lavina
            // 
            lavina.Location = new Point(1091, 59);
            lavina.Multiline = true;
            lavina.Name = "lavina";
            lavina.Size = new Size(670, 790);
            lavina.TabIndex = 20;
            // 
            // button4
            // 
            button4.Location = new Point(1332, 14);
            button4.Name = "button4";
            button4.Size = new Size(243, 34);
            button4.TabIndex = 19;
            button4.Text = "Эффект лавины";
            button4.UseVisualStyleBackColor = true;
            button4.Click += button4_Click;
            // 
            // IV
            // 
            IV.Location = new Point(6, 1028);
            IV.Multiline = true;
            IV.Name = "IV";
            IV.Size = new Size(1033, 46);
            IV.TabIndex = 18;
            // 
            // label5
            // 
            label5.AutoSize = true;
            label5.Location = new Point(19, 873);
            label5.Name = "label5";
            label5.Size = new Size(196, 25);
            label5.TabIndex = 16;
            label5.Text = "Зашифрованный текст";
            // 
            // text2
            // 
            text2.Location = new Point(6, 901);
            text2.Multiline = true;
            text2.Name = "text2";
            text2.Size = new Size(1033, 84);
            text2.TabIndex = 15;
            // 
            // button3
            // 
            button3.Location = new Point(837, 470);
            button3.Name = "button3";
            button3.Size = new Size(166, 34);
            button3.TabIndex = 14;
            button3.Text = "Расшифровать";
            button3.UseVisualStyleBackColor = true;
            button3.Click += button3_Click;
            // 
            // textBox1
            // 
            textBox1.Location = new Point(3, 525);
            textBox1.Multiline = true;
            textBox1.Name = "textBox1";
            textBox1.Size = new Size(1036, 324);
            textBox1.TabIndex = 13;
            // 
            // label4
            // 
            label4.AutoSize = true;
            label4.Location = new Point(12, 75);
            label4.Name = "label4";
            label4.Size = new Size(61, 25);
            label4.TabIndex = 12;
            label4.Text = "Байты";
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new Point(19, 212);
            label3.Name = "label3";
            label3.Size = new Size(45, 25);
            label3.TabIndex = 11;
            label3.Text = "HEX";
            // 
            // key2
            // 
            key2.Enabled = false;
            key2.Location = new Point(79, 194);
            key2.Multiline = true;
            key2.Name = "key2";
            key2.Size = new Size(455, 120);
            key2.TabIndex = 10;
            key2.TextChanged += key2_TextChanged;
            // 
            // key
            // 
            key.Enabled = false;
            key.Location = new Point(79, 59);
            key.Multiline = true;
            key.Name = "key";
            key.Size = new Size(455, 129);
            key.TabIndex = 9;
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new Point(696, 14);
            label2.Name = "label2";
            label2.Size = new Size(122, 25);
            label2.TabIndex = 8;
            label2.Text = "Введите текст";
            // 
            // text
            // 
            text.Location = new Point(553, 59);
            text.Multiline = true;
            text.Name = "text";
            text.Size = new Size(486, 385);
            text.TabIndex = 7;
            // 
            // button2
            // 
            button2.Location = new Point(173, 470);
            button2.Name = "button2";
            button2.Size = new Size(241, 34);
            button2.TabIndex = 5;
            button2.Text = "Сгенерировать ключ";
            button2.UseVisualStyleBackColor = true;
            button2.Click += button2_Click;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(232, 14);
            label1.Name = "label1";
            label1.Size = new Size(56, 25);
            label1.TabIndex = 3;
            label1.Text = "Ключ";
            label1.Click += label1_Click;
            // 
            // button1
            // 
            button1.Location = new Point(582, 470);
            button1.Name = "button1";
            button1.Size = new Size(166, 34);
            button1.TabIndex = 2;
            button1.Text = "Зашифровать";
            button1.UseVisualStyleBackColor = true;
            button1.Click += button1_Click;
            // 
            // tabPage4
            // 
            tabPage4.Controls.Add(proisv);
            tabPage4.Controls.Add(button5);
            tabPage4.Location = new Point(4, 34);
            tabPage4.Name = "tabPage4";
            tabPage4.Padding = new Padding(3);
            tabPage4.Size = new Size(1783, 1045);
            tabPage4.TabIndex = 3;
            tabPage4.Text = "Анализ распределения байтов";
            tabPage4.UseVisualStyleBackColor = true;
            // 
            // proisv
            // 
            proisv.Location = new Point(20, 145);
            proisv.Multiline = true;
            proisv.Name = "proisv";
            proisv.Size = new Size(1748, 864);
            proisv.TabIndex = 1;
            // 
            // button5
            // 
            button5.Location = new Point(701, 41);
            button5.Name = "button5";
            button5.Size = new Size(401, 55);
            button5.TabIndex = 0;
            button5.Text = "Анализ распределения байтов";
            button5.UseVisualStyleBackColor = true;
            button5.Click += button5_Click;
            // 
            // label6
            // 
            label6.AutoSize = true;
            label6.Location = new Point(19, 1000);
            label6.Name = "label6";
            label6.Size = new Size(28, 25);
            label6.TabIndex = 21;
            label6.Text = "IV";
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(10F, 25F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(1833, 1172);
            Controls.Add(tabControl1);
            Name = "Form1";
            Text = "Form1";
            tabControl1.ResumeLayout(false);
            tabPage1.ResumeLayout(false);
            tabPage1.PerformLayout();
            tabPage4.ResumeLayout(false);
            tabPage4.PerformLayout();
            ResumeLayout(false);
        }

        #endregion

        private RadioButton radio128;
        private RadioButton radio192;
        private RadioButton radio256;
        private TabControl tabControl1;
        private TabPage tabPage1;
        private TabPage tabPage4;
        private Button button1;
        private Label label1;
        private Button button2;
        private Label label2;
        private TextBox text;
        private TextBox key;
        private TextBox key2;
        private Label label4;
        private Label label3;
        private TextBox textBox1;
        private Button button3;
        private TextBox IV;
        private Label label5;
        private TextBox text2;
        private Button button4;
        private TextBox lavina;
        private Button button5;
        private TextBox proisv;
        private Label label6;
    }
}
