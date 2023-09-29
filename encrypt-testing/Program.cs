using System.Security.Cryptography;
using System.Text;

namespace encrypt_testing; 

class Program
{
    public static void Main()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        using var aes = new AesGcm(key);

        var nonce = new byte[AesGcm.NonceByteSizes.MaxSize]; // MaxSize = 12
        RandomNumberGenerator.Fill(nonce);
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        
        while (true)
        {
            Console.WriteLine("Hello! Input either 1, 2 or 0 for:\n");
            Console.WriteLine("1. Safely store message");
            Console.WriteLine("2. Read message");
            Console.WriteLine("0. Exit\n");
            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":

                    Console.WriteLine("Input text you want encrypted:");
                    string text = Console.ReadLine();
                    if (text == null)
                    {
                        Console.WriteLine("You didn't input text!!");
                    }
                    else
                    {
                        var plaintextBytes = Encoding.UTF8.GetBytes(text);
                        var ciphertext = new byte[plaintextBytes.Length];
                        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

                        string docPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                        using (StreamWriter outputFile =
                               new StreamWriter(
                                   Path.Combine(docPath, Directory.GetCurrentDirectory() + "\\encrypted.txt"),
                                   true))
                            //When just inputting "encrypted.txt" instead of GetCurrentDirectory()+"\\encrypted.txt" I would run into issues,
                            //where the encrypted text would save in another directory, therefore I tried this approach instead.

                        {
                            string ciphertextBase64 = Convert.ToBase64String(ciphertext);
                            outputFile.WriteLine(ciphertextBase64);
                        }

                        Console.WriteLine($"\n{text} has been encrypted and saved to encrypted.txt\n");
                    }

                    break;

                case "2":
                    try
                    {
                        /*using (var sr = new StreamReader("encrypted.txt"))
                        {
                            string encryptedBase64 = sr.ReadToEnd();
                            byte[] ciphertext = Convert.FromBase64String(encryptedBase64);
    
                            string decryptedText = Decrypt(ciphertext, nonce, tag, key);
    
                            Console.WriteLine("Decrypted Text: " + decryptedText);
                        }*/ //Had issues decrypting all the text in the text file now it only decrypts the latest message


                        var encryptedBase64 = File.ReadLines("encrypted.txt").Last();


                        byte[] ciphertext = Convert.FromBase64String(encryptedBase64);
                        string decryptedText = Decrypt(ciphertext, nonce, tag, key);
                        Console.WriteLine("\nDecrypted Text: " + decryptedText+"\n");
                    }
                    catch (IOException e)
                    {
                        Console.WriteLine("The file could not be read!");
                        Console.WriteLine(e.Message);
                    }

                    break;
                case "0":
                    File.WriteAllText("encrypted.txt", string.Empty);
                    Console.WriteLine("Exiting the program...");
                    return;

                default:
                    Console.WriteLine("You didn't input 1, 2 or 0.\n");
                    break;
            }
        }
    }

    private static string Decrypt(byte[] ciphertext, byte[] nonce, byte[] tag, byte[] key)
    {
        using (var aes = new AesGcm(key))
        {
            var plaintextBytes = new byte[ciphertext.Length];

            aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }
    }
}