using System.ComponentModel;
[assembly:Description("Onscript Decryptor")]

namespace NtDec
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Onscript Decryptor");
            Console.WriteLine("by Ulysses, wdwxy12345@gmail.com");

            if (args.Length == 0)
            {
                Console.WriteLine("Usage: NtDec <file> [encrypt_mode]");
                return;
            }

            string file = args[0];
            if (!File.Exists(file))
            {
                Console.WriteLine("File not found.");
                return;
            }

            var mode = 15;
            HashSet<int> supportedMode = [1,2,3,15,16,17];
            if (args.Length > 1)
            {
                if (!int.TryParse(args[1], out mode))
                {
                    Console.WriteLine("Invalid encrypt_mode.");
                    return;
                }

                if (!supportedMode.Contains(mode))
                {
                    Console.WriteLine($"encrypt_mode is not supported. Supported modes are: [{string.Join(',', supportedMode)}]");
                    return;
                }
            }
            else
            {
                //infer mode from file name
                var fileName = Path.GetFileName(file);
                switch (fileName)
                {
                    case "nscript.dat":
                        mode = 1;
                        break;
                    case "nscr_sec.dat":
                        mode = 2;
                        break;
                    case "nscript.___":
                        mode = 3;
                        break;
                    case "onscript.nt":
                        mode = 15;
                        break;
                    case "onscript.nt2":
                        mode = 16;
                        break;
                    case "onscript.nt3":
                        mode = 17;
                        break;
                }
            }

            byte[] data = File.ReadAllBytes(file);
            byte[] decrypted;
            switch (mode)
            {
                case 1:
                    decrypted = ProcessV1(data);
                    break;
                case 2:
                    decrypted = ProcessV2(data);
                    break;
                case 3:
                    var keyExe = "key.exe";
                    if (!File.Exists(keyExe))
                    {
                        keyExe = Path.Combine(Path.GetDirectoryName(file) ?? "", "key.exe");
                        if(!File.Exists(keyExe))
                        {
                            Console.WriteLine("key.exe not found. Please rename key file to key.exe and put it to the same position as nscript file.");
                            return;
                        }
                    }
                    decrypted = ProcessV3(data, keyExe);
                    break;
                case 15:
                    decrypted = ProcessV15(data);
                    break;
                case 16:
                    decrypted = ProcessV16(data);
                    break;
                case 17:
                    decrypted = ProcessV17(data);
                    break;
                case 18:
                    decrypted = ProcessV18(data);
                    break;
                default:
                    Console.WriteLine("encrypt_mode unsupported yet.");
                    return;
            }
            
            File.WriteAllBytes(file + ".txt", decrypted);
            Console.WriteLine("Done.");
        }

        static byte[] ProcessV1(byte[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte)(data[i] ^ 0x84);
            }
            return data;
        }

        static byte[] ProcessV2(byte[] data)
        {
            var magic = new byte[] {0x79, 0x57, 0x0d, 0x80, 0x04};
            var counter = 0;
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte)(data[i] ^ magic[counter]);
                counter = (counter + 1) % magic.Length;
            }
            return data;
        }

        static byte[] ProcessV3(byte[] data, string keyExe)
        {
            if (!File.Exists(keyExe))
            {
                return data;
            }

            byte[] keys = new byte[0x100];
            for (int i = 0; i < keys.Length; i++)
            {
                keys[i] = (byte)i;
            }

            using var fs = File.OpenRead(keyExe);
            using var br = new BinaryReader(fs);

            int ring_start = 0, ring_last = 0;
            byte[] ring_buffer = new byte[0x100];
            byte ch = 0;
            while (br.BaseStream.Position < fs.Length)
            {
                ch = br.ReadByte();
                int i = ring_start;
                var count = 0;
                while (i != ring_last && ring_buffer[i] != ch)
                {
                    count++;
                    i = (i + 1) % 256;
                }
                if (i == ring_last && count == 255) break;
                if (i != ring_last)
                    ring_start = (i + 1) % 256;
                ring_buffer[ring_last] = ch;
                ring_last = (ring_last + 1) % 256;
            }

            // Key table creation
            ring_buffer[ring_last] = ch;
            for (int i = 0; i < 256; i++)
                keys[ring_buffer[(ring_start + i) % 256]] = (byte)i;
            

            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte) (keys[data[i]] ^ 0x84);
            }
            return data;
        }

        /// <summary>
        /// used in 15, 17
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        static byte[] Process2Bytes(byte[] data)
        {
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

        static byte[] ProcessV15(byte[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte) ((data[i] ^ 0x85) - 1);
            }

            Process2Bytes(data);

            return data;
        }

        static byte[] ProcessV16(byte[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                data[i] = (byte)((data[i] ^ 0x85) - 1);
            }

            return data;
        }

        static byte[] ProcessV17(byte[] data)
        {
            if (data[0] == 'P' && data[1] == 'K')
            {
                return ProcessV18(data);
            }

            if (data.Length < 4000)
            {
                for (int i = 0; i < data.Length; i++)
                {
                    data[i] ^= 0x98; //24^0x80&0x93
                }
                return data;
            }

            var vm = new Taiga();
            for (int i = 0; i < data.Length; i++)
            {
                data[i] ^= (byte)(vm.choose() ^ vm.myxor());
                data[i] -= 1; //vm.sum(data[i]); //optimized :<
            }

            data = Process2Bytes(data);
            return data;
        }

        static byte[] ProcessV18(byte[] data)
        {
            bool newlineFlag = true;
            const int mainKey = 0x5D588B65;

            if (data.Length <= 2336)
            {
               Console.WriteLine("NT3Decoder: invalid nt3 script.");
               return data;
            }

            int size = data.Length - 2336;
            var key = BitConverter.ToInt32(data, 2332);

            byte[] buffer = new byte[size];
            Array.Copy(data, 2336, buffer, 0, size);

            int ptr = 0;
            for (int i = 1; i <= size; i++)
            {
                var buf = buffer[ptr];
                key = buf ^ key;
                key += mainKey + buf * (size - i + 1);
                buffer[ptr] ^= (byte)key;
                buf = buffer[ptr];
                if (buf == '*' && newlineFlag)
                {
                    // num_of_labels++;
                }

                if (buf == '\n')
                {
                    newlineFlag = true;
                }
                else
                {
                    if (buf != ' ' && buf != '\t')
                    {
                        newlineFlag = false;
                    }
                }

                ptr++;
            }

            buffer[^1] = 0x0A;

            return buffer;
        }
    }
}
