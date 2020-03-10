### TODO:
- Rename `inputBytes` to `bytes` for consistency in RSA methods

### Alternative code to look into fixing later

Some code, which as I was writing the main solution didn't work as expected and I wanted to come back to it later, when main functionality is completed. This is just my notes, I'd prefer `while` loop instead of `for` loop in the RSA methods, just my preference.

#### Code for RSA enctyption/decryption methods
```
// TODO: add offset caculation to make it work
int length = 0;
byte[] buffer = new byte[cipher.GetInputBlockSize()];
inputMemory.Seek(0, SeekOrigin.Begin);
while ((length = inputMemory.Read(buffer, 0, buffer.Length)) > 0)
{
    byte[] ciphered = cipher.ProcessBlock(buffer, 0, length);
    outputMemory.Write(ciphered, 0, ciphered.Length);
}
```
