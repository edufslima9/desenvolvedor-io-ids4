using System.ComponentModel.DataAnnotations;

namespace SkyCommerce.Site.Models
{
    public class EsqueciSenhaViewModel
    {
        [Required(ErrorMessage = "Preencha o campo E-mail")]
        [EmailAddress(ErrorMessage = "O e-mail informado não é válido")]
        public string Email { get; set; }
    }
}
