using Org.BouncyCastle.OpenSsl;

namespace BCCrypto
{
	public class PasswordFinder : IPasswordFinder
	{
		private readonly char[] password;

		public PasswordFinder(char[] word)
		{
			this.password = (char[])word.Clone();
		}

		public char[] GetPassword()
		{
			return (char[])password.Clone();
		}
	}
}
