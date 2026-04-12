using System;
using Microsoft.Extensions.Logging;

namespace Example
{
    public class UserService
    {
        private readonly ILogger _logger;

        public string Email { get; set; }
        public string FullName { get; set; }
        public string PhoneNumber { get; set; }
        public string Password { get; set; }

        public void ProcessUser()
        {
            _logger.LogInformation("Processing: " + Email);
            Console.WriteLine(FullName);

            string creditCard = GetCreditCard();
            var ssn = GetSSN();
        }

        private string GetCreditCard() => "4111111111111111";
        private string GetSSN() => "123-45-6789";
    }
}
