namespace NtDec
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("onscript.nt (encrypt_mode=15) Decryptor");
            Console.WriteLine("by Ulysses, wdwxy12345@gmail.com");

            if (args.Length == 0)
            {
                Console.WriteLine("Usage: NtDec <file>");
                return;
            }

            string file = args[0];
            if (!File.Exists(file))
            {
                Console.WriteLine("File not found.");
                return;
            }

            byte[] data = File.ReadAllBytes(file);
            byte[] decrypted = Process(data);
            File.WriteAllBytes(file + ".txt", decrypted);
            Console.WriteLine("Done.");
        }

        static byte[] Process(byte[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte) ((data[i] ^ 0x85) - 1);
            }

            Span<byte> span = data;
            for (int i = 0; i < span.Length - 1; i++)
            {
                var s = span.Slice(i, 2);
                //if (i == 956023)
                //{
                //    Console.WriteLine();
                //}
                if (MmrankTable.OnsLocaleIsTwoBytes(s))
                {
                    MmrankTable.OnsGetUnencryptionShort(s);
                    i++;
                }
                else if (MmrankTable.PostFix(s))
                {
                    i++;
                }
            }

            return data;
        }
    }
}
