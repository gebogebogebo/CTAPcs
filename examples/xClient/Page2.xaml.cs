﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace xClient
{
    /// <summary>
    /// Page2.xaml の相互作用ロジック
    /// </summary>
    public partial class Page2 : Page
    {
        private static Page3 page = null;

        public Page2()
        {
            InitializeComponent();
        }

        private void ButtonPasteRPID_Click(object sender, RoutedEventArgs e)
        {
            this.TextRPID.Paste();
        }

        private void ButtonPasteChallenge_Click(object sender, RoutedEventArgs e)
        {
            this.TextChallenge.Paste();
        }

        private void ButtonNext_Click(object sender, RoutedEventArgs e)
        {
            var app = (MainWindow)Application.Current.MainWindow;
            app.RPID = this.TextRPID.Text;
            if(!string.IsNullOrEmpty(TextRPID.Text)) {
                app.Challenge = g.FIDO2.Common.HexStringToBytes(TextChallenge.Text);
            }

            if (page == null) page = new Page3();
            this.NavigationService.Navigate(page);
        }
    }
}
