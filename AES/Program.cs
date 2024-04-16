using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


namespace AES
{
    class Program
    {
        static byte[] key = new byte[] {
            1, 2, 3, 4,
            5, 6, 7, 8,
            9, 10, 11, 12,
            13, 14, 15, 16 };
        static byte[] InitVec = new byte[] {
            16, 15, 14, 13,
            12, 11, 10, 9,
            8, 7, 6, 5,
            4, 3, 2, 1 };
        static byte[] MyData = new byte[] {
            1, 2, 3, 4,
            5, 6, 7, 8,
            9, 10, 11, 12,
            13, 14, 15, 16 };

        static byte myleft(byte input, int p)
        {
            p = p % 8;
            int mask = 0b_1111_1111_0000_0000;
            int temp = input << p;
            return (byte)(temp | ((temp & mask) >> 8));
        }

        static byte[] gmul_inverseTable = new byte[] {
             0x00 ,0x01 ,0x8d ,0xf6 ,0xcb ,0x52 ,0x7b ,0xd1 ,0xe8 ,0x4f ,0x29 ,0xc0 ,0xb0 ,0xe1 ,0xe5 ,0xc7
            ,0x74 ,0xb4 ,0xaa ,0x4b ,0x99 ,0x2b ,0x60 ,0x5f ,0x58 ,0x3f ,0xfd ,0xcc ,0xff ,0x40 ,0xee ,0xb2
            ,0x3a ,0x6e ,0x5a ,0xf1 ,0x55 ,0x4d ,0xa8 ,0xc9 ,0xc1 ,0x0a ,0x98 ,0x15 ,0x30 ,0x44 ,0xa2 ,0xc2
            ,0x2c ,0x45 ,0x92 ,0x6c ,0xf3 ,0x39 ,0x66 ,0x42 ,0xf2 ,0x35 ,0x20 ,0x6f ,0x77 ,0xbb ,0x59 ,0x19
            ,0x1d ,0xfe ,0x37 ,0x67 ,0x2d ,0x31 ,0xf5 ,0x69 ,0xa7 ,0x64 ,0xab ,0x13 ,0x54 ,0x25 ,0xe9 ,0x09
            ,0xed ,0x5c ,0x05 ,0xca ,0x4c ,0x24 ,0x87 ,0xbf ,0x18 ,0x3e ,0x22 ,0xf0 ,0x51 ,0xec ,0x61 ,0x17
            ,0x16 ,0x5e ,0xaf ,0xd3 ,0x49 ,0xa6 ,0x36 ,0x43 ,0xf4 ,0x47 ,0x91 ,0xdf ,0x33 ,0x93 ,0x21 ,0x3b
            ,0x79 ,0xb7 ,0x97 ,0x85 ,0x10 ,0xb5 ,0xba ,0x3c ,0xb6 ,0x70 ,0xd0 ,0x06 ,0xa1 ,0xfa ,0x81 ,0x82
            ,0x83 ,0x7e ,0x7f ,0x80 ,0x96 ,0x73 ,0xbe ,0x56 ,0x9b ,0x9e ,0x95 ,0xd9 ,0xf7 ,0x02 ,0xb9 ,0xa4
            ,0xde ,0x6a ,0x32 ,0x6d ,0xd8 ,0x8a ,0x84 ,0x72 ,0x2a ,0x14 ,0x9f ,0x88 ,0xf9 ,0xdc ,0x89 ,0x9a
            ,0xfb ,0x7c ,0x2e ,0xc3 ,0x8f ,0xb8 ,0x65 ,0x48 ,0x26 ,0xc8 ,0x12 ,0x4a ,0xce ,0xe7 ,0xd2 ,0x62
            ,0x0c ,0xe0 ,0x1f ,0xef ,0x11 ,0x75 ,0x78 ,0x71 ,0xa5 ,0x8e ,0x76 ,0x3d ,0xbd ,0xbc ,0x86 ,0x57
            ,0x0b ,0x28 ,0x2f ,0xa3 ,0xda ,0xd4 ,0xe4 ,0x0f ,0xa9 ,0x27 ,0x53 ,0x04 ,0x1b ,0xfc ,0xac ,0xe6
            ,0x7a ,0x07 ,0xae ,0x63 ,0xc5 ,0xdb ,0xe2 ,0xea ,0x94 ,0x8b ,0xc4 ,0xd5 ,0x9d ,0xf8 ,0x90 ,0x6b
            ,0xb1 ,0x0d ,0xd6 ,0xeb ,0xc6 ,0x0e ,0xcf ,0xad ,0x08 ,0x4e ,0xd7 ,0xe3 ,0x5d ,0x50 ,0x1e ,0xb3
            ,0x5b ,0x23 ,0x38 ,0x34 ,0x68 ,0x46 ,0x03 ,0x8c ,0xdd ,0x9c ,0x7d ,0xa0 ,0xcd ,0x1a ,0x41 ,0x1c
        };
        /// <summary>
        /// 嘎羅瓦域反函數運算
        /// </summary>
        /// <param name="b"></param>
        /// <returns></returns>
        static byte gmul_inverse(byte b)
        {
            return gmul_inverseTable[b];
            //此有限域為輸入*輸出 並以XOR 進行類常除法得1的答案。(輸入為0輸出為0)
            //const int mod = 0b_100011011;

            //return b;
        }

        static byte S_Box(byte b)
        {
            b = gmul_inverse(b);
            byte s = (byte)(b ^ myleft(b, 1) ^ myleft(b, 2) ^ myleft(b, 3) ^ myleft(b, 4) ^ 99);
            return s;
        }
        static byte InverseS_Box(byte b)
        {
            byte s = (byte)(myleft(b, 1) ^ myleft(b, 3) ^ myleft(b, 6) ^ 5);
            return gmul_inverse(s);
        }

        static void Main(string[] args)
        {
            MyAes myAes = new MyAes();
            myAes.Key = new byte[] {
               0x49 ,0x20 ,0xe2 ,0x99 ,0xa5 ,0x20 ,0x52 ,0x61 ,0x64 ,0x69 ,0x6f ,0x47 ,0x61 ,0x74 ,0x75 ,0x6e
            };
            myAes.Key = key;
            byte[] myEncrypttest = myAes.Encrypt(MyData);
            string encryptData = Convert.ToBase64String(myEncrypttest);
            Console.WriteLine(encryptData);
            DefaultMeth();
        }

        private static void DefaultMeth()
        {
            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();

            aes.Key = key;
            aes.IV = InitVec;
            string encryptData = "";
            using (MemoryStream ms = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(MyData, 0, MyData.Length);
                cs.FlushFinalBlock();
                byte[] bts = ms.ToArray();
                BigInteger bit = new BigInteger(bts);
                Console.WriteLine(bit.ToString());
                encryptData = Convert.ToBase64String(bts);
            }
            Console.WriteLine(encryptData);
            Console.ReadLine();
        }
    }
    public class MyAes
    {
        public byte[] SBOX = null;
        public byte[] ISBOX = null;
        public byte[] Key = null;
        public byte[] IV = null;
        public byte[] WordByte = null;

        public MyAes()
        {
            SBOX = new byte[256];
            ISBOX = new byte[256];
            for (int i = 0; i < SBOX.Length; i++)
            {
                SBOX[i] = S_Box((byte)i);
                ISBOX[SBOX[i]] = (byte)i;
            }
        }

        public byte[] Encrypt(byte[] input)
        {
            //DisplayrM(input);
            byte[] WordByte = makeW();
            byte[] temp = input.ToArray();
            AddRoundKey(temp, 0);
            for (int i = 0; i < 9; i++)
            {
                S_Box(temp);
                //DisplayrM(temp);
                ShiftRows(temp);
                //DisplayrM(temp);
                RowMix(temp);
                AddRoundKey(temp, (i + 1) * 4);

            }
            S_Box(temp);
            ShiftRows(temp);
            AddRoundKey(temp, 40);
            return temp;
        }

        void AddRoundKey(byte[] input, int wordPosit)
        {
            byte[] CurrentKey = new byte[16];

            for (int i = 0; i < CurrentKey.Length; i++)
            {
                CurrentKey[i] = WordByte[wordPosit * 4 + i];
            }
            for (int i = 0; i < input.Length; i++)
            {
                input[i] = (byte)(input[i] ^ CurrentKey[i]);
            }
        }


        byte[] makeW()
        {
            const int Wleng = 4;

            byte[] Wtemp = new byte[Wleng];
            byte[] rtn = new byte[44 * Wleng];
            for (int i = 0; i < 4 * Wleng; i++)
            {
                rtn[i] = Key[i];
            }
            for (int i = 4 * Wleng; i < 44 * Wleng; i += Wleng)
            {
                int Wi = i / Wleng;
                Wtemp[0] = rtn[(Wi - 1) * Wleng];
                Wtemp[1] = rtn[(Wi - 1) * Wleng + 1];
                Wtemp[2] = rtn[(Wi - 1) * Wleng + 2];
                Wtemp[3] = rtn[(Wi - 1) * Wleng + 3];

                if (Wi % 4 == 0)
                {
                    Wtemp = Func_g(Wtemp, Wi);
                }

                rtn[Wi * Wleng] = (byte)(rtn[(Wi - 4) * Wleng] ^ Wtemp[0]);
                rtn[Wi * Wleng + 1] = (byte)(rtn[(Wi - 4) * Wleng + 1] ^ Wtemp[1]);
                rtn[Wi * Wleng + 2] = (byte)(rtn[(Wi - 4) * Wleng + 2] ^ Wtemp[2]);
                rtn[Wi * Wleng + 3] = (byte)(rtn[(Wi - 4) * Wleng + 3] ^ Wtemp[3]);
            }
            WordByte = rtn;
            return rtn;
        }

        static byte[] Func_g(byte[] Input, int index)
        {
            byte[] rtn = new byte[] { Input[1], Input[2], Input[3], Input[0], };
            byte[] Rconi = Rcon(index);
            for (int i = 0; i < rtn.Length; i++)
            {
                rtn[i] = S_Box(rtn[i]);
                rtn[i] = (byte)(rtn[i] ^ Rconi[i]);
            }
            return rtn;
        }

        static byte[] Rcon(int i)
        {
            i = i / 4;
            byte[] RC = new byte[] { 00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, };
            return new byte[] { RC[i], 0, 0, 0 };
        }

        static byte[] gmul_inverseTable = new byte[] {
             0x00 ,0x01 ,0x8d ,0xf6 ,0xcb ,0x52 ,0x7b ,0xd1 ,0xe8 ,0x4f ,0x29 ,0xc0 ,0xb0 ,0xe1 ,0xe5 ,0xc7
            ,0x74 ,0xb4 ,0xaa ,0x4b ,0x99 ,0x2b ,0x60 ,0x5f ,0x58 ,0x3f ,0xfd ,0xcc ,0xff ,0x40 ,0xee ,0xb2
            ,0x3a ,0x6e ,0x5a ,0xf1 ,0x55 ,0x4d ,0xa8 ,0xc9 ,0xc1 ,0x0a ,0x98 ,0x15 ,0x30 ,0x44 ,0xa2 ,0xc2
            ,0x2c ,0x45 ,0x92 ,0x6c ,0xf3 ,0x39 ,0x66 ,0x42 ,0xf2 ,0x35 ,0x20 ,0x6f ,0x77 ,0xbb ,0x59 ,0x19
            ,0x1d ,0xfe ,0x37 ,0x67 ,0x2d ,0x31 ,0xf5 ,0x69 ,0xa7 ,0x64 ,0xab ,0x13 ,0x54 ,0x25 ,0xe9 ,0x09
            ,0xed ,0x5c ,0x05 ,0xca ,0x4c ,0x24 ,0x87 ,0xbf ,0x18 ,0x3e ,0x22 ,0xf0 ,0x51 ,0xec ,0x61 ,0x17
            ,0x16 ,0x5e ,0xaf ,0xd3 ,0x49 ,0xa6 ,0x36 ,0x43 ,0xf4 ,0x47 ,0x91 ,0xdf ,0x33 ,0x93 ,0x21 ,0x3b
            ,0x79 ,0xb7 ,0x97 ,0x85 ,0x10 ,0xb5 ,0xba ,0x3c ,0xb6 ,0x70 ,0xd0 ,0x06 ,0xa1 ,0xfa ,0x81 ,0x82
            ,0x83 ,0x7e ,0x7f ,0x80 ,0x96 ,0x73 ,0xbe ,0x56 ,0x9b ,0x9e ,0x95 ,0xd9 ,0xf7 ,0x02 ,0xb9 ,0xa4
            ,0xde ,0x6a ,0x32 ,0x6d ,0xd8 ,0x8a ,0x84 ,0x72 ,0x2a ,0x14 ,0x9f ,0x88 ,0xf9 ,0xdc ,0x89 ,0x9a
            ,0xfb ,0x7c ,0x2e ,0xc3 ,0x8f ,0xb8 ,0x65 ,0x48 ,0x26 ,0xc8 ,0x12 ,0x4a ,0xce ,0xe7 ,0xd2 ,0x62
            ,0x0c ,0xe0 ,0x1f ,0xef ,0x11 ,0x75 ,0x78 ,0x71 ,0xa5 ,0x8e ,0x76 ,0x3d ,0xbd ,0xbc ,0x86 ,0x57
            ,0x0b ,0x28 ,0x2f ,0xa3 ,0xda ,0xd4 ,0xe4 ,0x0f ,0xa9 ,0x27 ,0x53 ,0x04 ,0x1b ,0xfc ,0xac ,0xe6
            ,0x7a ,0x07 ,0xae ,0x63 ,0xc5 ,0xdb ,0xe2 ,0xea ,0x94 ,0x8b ,0xc4 ,0xd5 ,0x9d ,0xf8 ,0x90 ,0x6b
            ,0xb1 ,0x0d ,0xd6 ,0xeb ,0xc6 ,0x0e ,0xcf ,0xad ,0x08 ,0x4e ,0xd7 ,0xe3 ,0x5d ,0x50 ,0x1e ,0xb3
            ,0x5b ,0x23 ,0x38 ,0x34 ,0x68 ,0x46 ,0x03 ,0x8c ,0xdd ,0x9c ,0x7d ,0xa0 ,0xcd ,0x1a ,0x41 ,0x1c
        };
        static byte gmul(byte a, byte b)
        {
            byte p = 0;
            byte counter;
            byte hi_bit_set;
            for (counter = 0; counter < 8; counter++)
            {
                if ((b & 1) == 1)
                    p ^= a;
                hi_bit_set = ((byte)(a & 0x80));
                a <<= 1;
                if (hi_bit_set == 0x80)
                    a ^= 0x1b;
                b >>= 1;
            }
            return p;
        }
        /// <summary>
        /// 列混淆當列運算
        /// </summary>
        /// <param name="r"></param>
        static void gmix_column(byte[] r)
        {
            //https://www.samiam.org/mix-column.html
            byte[] a = new byte[4];
            byte c;
            for (c = 0; c < 4; c++)
            {
                a[c] = r[c];
            }
            r[0] = (byte)(gmul(a[0], 2) ^ gmul(a[3], 1) ^ gmul(a[2], 1) ^ gmul(a[1], 3));
            r[1] = (byte)(gmul(a[1], 2) ^ gmul(a[0], 1) ^ gmul(a[3], 1) ^ gmul(a[2], 3));
            r[2] = (byte)(gmul(a[2], 2) ^ gmul(a[1], 1) ^ gmul(a[0], 1) ^ gmul(a[3], 3));
            r[3] = (byte)(gmul(a[3], 2) ^ gmul(a[2], 1) ^ gmul(a[1], 1) ^ gmul(a[0], 3));
        }
        static void RowMix(byte[] data)
        {
            for (int i = 0; i < 4; i++)
            {
                byte[] mixuse = new byte[] { data[4 * i + 0], data[4 * i + 1], data[4 * i + 2], data[4 * i + 3], };
                gmix_column(mixuse);
                data[4 * i + 0] = mixuse[0];
                data[4 * i + 1] = mixuse[1];
                data[4 * i + 2] = mixuse[2];
                data[4 * i + 3] = mixuse[3];
            }
        }
        /// <summary>
        /// 嘎羅瓦域反函數運算
        /// </summary>
        /// <param name="b"></param>
        /// <returns></returns>
        static byte gmul_inverse(byte b)
        {
            return gmul_inverseTable[b];
        }

        static byte S_Box(byte b)
        {
            b = gmul_inverse(b);
            byte s = (byte)(b ^ myleft(b, 1) ^ myleft(b, 2) ^ myleft(b, 3) ^ myleft(b, 4) ^ 99);
            return s;
        }
        static byte InverseS_Box(byte b)
        {
            byte s = (byte)(myleft(b, 1) ^ myleft(b, 3) ^ myleft(b, 6) ^ 5);
            return gmul_inverse(s);
        }
        void S_Box(byte[] b)
        {
            for (int i = 0; i < b.Length; i++)
            {
                b[i] = SBOX[b[i]];
            }
        }
        void InverseS_Box(byte[] b)
        {
            for (int i = 0; i < b.Length; i++)
            {
                b[i] = ISBOX[b[i]];
            }
        }

        static byte myleft(byte input, int p)
        {
            p = p % 8;
            int mask = 0b_1111_1111_0000_0000;
            int temp = input << p;
            return (byte)(temp | ((temp & mask) >> 8));
        }
        static void ShiftRows(byte[] input)
        {
            for (int row = 1; row < 4; row++)
            {
                byte[] tempArr = new byte[row];
                for (int tri = 0; tri < tempArr.Length; tri++)
                {
                    tempArr[tri] = input[row + 4 * tri];
                }
                for (int tri = 0; tri < 4 - tempArr.Length; tri++)
                {
                    input[row + 4 * tri] = input[row + 4 * (tri + tempArr.Length)];
                }
                for (int tri = 4 - tempArr.Length; tri < 4; tri++)
                {
                    input[row + 4 * tri] = tempArr[(tri - 4 + tempArr.Length)];
                }

                //0123
                //1230
                //2301
                //3012

                //301
                //230
                //123
            }
        }

        public static void DisplayrM(byte[] input)
        {
            for (byte y = 0; y < 4; y++)
            {
                for (byte x = 0; x < 4; x++)
                {
                    Console.Write(input[y + x * 4].ToString("000"));
                    Console.Write(" ");
                }
                Console.WriteLine();
            }
            Console.WriteLine("=====================================");
        }

        static void leftRotate(int[] arr, int d,
                        int n)
        {
            int i, j, k, temp;
            /* To handle if d >= n */
            d = d % n;
            int g_c_d = gcd(d, n);
            for (i = 0; i < g_c_d; i++)
            {
                /* move i-th values of blocks */
                temp = arr[i];
                j = i;
                while (true)
                {
                    k = j + d;
                    if (k >= n)
                        k = k - n;
                    if (k == i)
                        break;
                    arr[j] = arr[k];
                    j = k;
                }
                arr[j] = temp;
            }

            /* Function to get gcd of a and b*/
            static int gcd(int a, int b)
            {
                if (b == 0)
                    return a;
                else
                    return gcd(b, a % b);
            }
        }

    }
}