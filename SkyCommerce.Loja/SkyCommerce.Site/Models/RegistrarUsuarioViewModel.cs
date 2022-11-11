using System.ComponentModel.DataAnnotations;

namespace SkyCommerce.Site.Models
{
    public class RegistrarUsuarioViewModel
    {
        [Required(ErrorMessage = "Preencha o campo E-mail")]
        [EmailAddress(ErrorMessage = "O e-mail informado não é válido")]
        public string Email { get; set; }

        public string Nome { get; set; }

        [Required(ErrorMessage = "Preencha o campo Senha")]
        [StringLength(100, ErrorMessage = "A senha deve possuir no mínimo 6 e no máximo 100 caracteres", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Senha")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Preencha o campo Confirmação de Senha")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirme a Senha")]
        [Compare("Password", ErrorMessage = "As senhas informadas não se coincidem")]
        public string ConfirmPassword { get; set; }

    }
}
