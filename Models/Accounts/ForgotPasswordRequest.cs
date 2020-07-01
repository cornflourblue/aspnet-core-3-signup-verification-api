using System.ComponentModel.DataAnnotations;

namespace WebApi.Models.Accounts
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}