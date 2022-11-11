using System.ComponentModel.DataAnnotations;

namespace SkyCommerce.Site.Models
{
    public class ResetPasswordViewModel
    {
        [Required(ErrorMessage = "Preencha o campo E-mail")]
        [EmailAddress(ErrorMessage = "O endereço informado não é válido")]
        [Display(Name = "E-mail")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Preencha a nova senha.")]
        [StringLength(20, ErrorMessage = "A senha precisa ter no mínimo 6 e no máximo 20 caracteres.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [Display(Name = "Nova Senha")]
        public string Password { get; set; }

        [Required(ErrorMessage = "Preencha a confirmação de nova senha.")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirme a nova Senha")]
        [Compare("Password", ErrorMessage = "As senhas não conferem.")]
        public string ConfirmPassword { get; set; }

        public string Code { get; set; }
    }
}
