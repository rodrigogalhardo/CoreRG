//------------------------------------------------------------------------------
// <auto-generated>
//    This code was generated from a template.
//
//    Manual changes to this file may cause unexpected behavior in your application.
//    Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace CoreRG
{
    using System;
    using System.Collections.Generic;
    
    public partial class Pedidos
    {
        public int IdPedido { get; set; }
        public int CardId { get; set; }
        public int IdCadastro { get; set; }
        public System.DateTime DataPedido { get; set; }
        public string EnderecoEntrega { get; set; }
        public decimal TotalDoPedido { get; set; }
    }
}