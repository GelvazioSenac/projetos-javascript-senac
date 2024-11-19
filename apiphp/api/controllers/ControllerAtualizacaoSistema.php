<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;

/**
 * Chamada da api Sistema
 *
 * User: Gelvazio Camargo
 * Date: 10/12/2020
 * Time: 17:40
 */
require_once("ControllerApiBase.php");
class ControllerAtualizacaoSistema extends ControllerApiBase {

    public function atualizaSistema(Request $request, Response $response, array $args) {
        $sSql = "SELECT siscodigo, sisnome, sisativo FROM sistemas ORDER BY siscodigo";

        // Executa a query de atualização
        $this->getQuery()->query($sSql);

        $data = array("Atualizando banco de dados... " => date("Y-m-d H:i:s"));

        return $response->withJson($data, 200);
    }

    private function executaAtualizacao() {
        $sSql_atualizacao_inicial = " CREATE TABLE public.usuario (
                    cd_usuario int2 NOT NULL,
                    ds_login varchar(20) NOT NULL,
                    ds_usuario varchar(35) NOT NULL,
                    ds_senha varchar(10) NULL,
                    cd_grupo int4 NOT NULL,
                    dt_alt date NOT NULL,
                    hr_alt time NOT NULL,
                    dt_cad date NOT NULL,
                    hr_cad time NOT NULL,
                    cd_filial int4 NOT NULL,
                    fg_ativo int2 NOT NULL DEFAULT 1,
                    CONSTRAINT usuario_pk PRIMARY KEY (cd_usuario)
                );
                
                CREATE TABLE public.menu (
                    mencodigo int4 NOT NULL,
                    siscodigo int4 NOT NULL,
                    mennome varchar(200) NULL,
                    mentabela varchar(200) NULL,
                    CONSTRAINT pk_menu PRIMARY KEY (mencodigo, siscodigo)
                );
                
                CREATE TABLE public.sistema (
                    siscodigo int4 NOT NULL,
                    sisnome varchar(200) NULL,
                    sisativo int2 NOT NULL DEFAULT 0,
                    CONSTRAINT pk_sistema PRIMARY KEY (siscodigo)
                );
                
                -- Permissions
                
                ALTER TABLE public.sistema OWNER TO ftgcyhzw;
                GRANT ALL ON TABLE public.sistema TO ftgcyhzw;
                
                ALTER TABLE public.menu OWNER TO ftgcyhzw;
                GRANT ALL ON TABLE public.menu TO ftgcyhzw;
                
                ALTER TABLE public.usuario OWNER TO ftgcyhzw;
                GRANT ALL ON TABLE public.usuario TO ftgcyhzw;
                
                CREATE TABLE contacts (
                      id serial NOT NULL,
                      email varchar(255) NOT NULL,
                      name varchar(255) NOT NULL,
                      phone varchar(255) NOT NULL
                    )
                    CREATE SEQUENCE contacts_id_seq
                         INCREMENT 1
                         MINVALUE 1
                         MAXVALUE 9223372036854775807
                         START 1
                         CACHE 1;
                       
                       --reinicia a sequence com 200 
                       ALTER SEQUENCE contacts_id_seq RESTART WITH 200; 

                    
                    INSERT INTO contacts (id, email, name, phone) VALUES
                    (1, 'contact0@blog.com.br', 'Contact0', '(000) 000-0000'),
                    (2, 'contact1@blog.com.br', 'Contact1', '(000) 000-0000'),
                    (3, 'contact2@blog.com.br', 'Contact2', '(000) 000-0000'),
                    (4, 'contact3@blog.com.br', 'Contact3', '(000) 000-0000'),
                    (5, 'contact4@blog.com.br', 'Contact4', '(000) 000-0000'),
                    (6, 'contact5@blog.com.br', 'Contact5', '(000) 000-0000'),
                    (7, 'contact6@blog.com.br', 'Contact6', '(000) 000-0000'),
                    (8, 'contact7@blog.com.br', 'Contact7', '(000) 000-0000'),
                    (9, 'contact8@blog.com.br', 'Contact8', '(000) 000-0000'),
                    (10, 'contact9@blog.com.br', 'Contact9', '(000) 000-0000'),
                    (11, 'contact10@blog.com.br', 'Contact10', '(000) 000-0000'),
                    (12, 'contact11@blog.com.br', 'Contact11', '(000) 000-0000'),
                    (13, 'contact12@blog.com.br', 'Contact12', '(000) 000-0000');

                INSERT INTO public.sistema
                (siscodigo, sisnome, sisativo)
                VALUES(3, 'FINANCEIRO', 1);
                INSERT INTO public.sistema
                (siscodigo, sisnome, sisativo)
                VALUES(1, 'CADASTRO', 1);
                INSERT INTO public.sistema
                (siscodigo, sisnome, sisativo)
                VALUES(2, 'FATURAMENTO', 1);
                INSERT INTO public.sistema
                (siscodigo, sisnome, sisativo)
                VALUES(4, 'BOLETO BANCÁRIO', 1);
                INSERT INTO public.sistema
                (siscodigo, sisnome, sisativo)
                VALUES(5, 'SUPRIMENTOS', 1);
                INSERT INTO public.sistema
                (siscodigo, sisnome, sisativo)
                VALUES(6, 'ENGENHARIA', 1);
                INSERT INTO public.sistema
                (siscodigo, sisnome, sisativo)
                VALUES(7, 'RELATÓRIOS', 1);
                INSERT INTO public.sistema
                (siscodigo, sisnome, sisativo)
                VALUES(8, 'ESTRUTURA', 1);
                
                
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(1, 1, 'PRODUTO', 'PRODUTO');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(2, 1, 'PESSOA', 'PESSOA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(3, 1, 'VENDEDOR', 'VENDEDOR');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(4, 1, 'TRANSPORTADORA', 'TRANSPORTADORA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(5, 1, 'FORNECEDOR', 'FORNECEDOR');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(6, 1, 'CIDADE', 'CIDADE');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(7, 1, 'MUNICIPIO', 'MUNICIPIO');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(8, 1, 'REGIÃO', 'REGIÃO');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(9, 1, 'UNIDADE DE MEDIDA', 'UNIDADE DE MEDIDA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(1, 2, 'NOTA DE ENTRADA', 'NOTA DE ENTRADA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(2, 2, 'NOTA DE SERVIÇOS', 'NOTA DE SERVIÇOS');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(3, 2, 'GERENCIADOR NFE', 'GERENCIADOR NFE');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(4, 2, 'GERENCIADOR NFSE', 'GERENCIADOR NFSE');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(5, 2, 'ORÇAMENTO', 'ORÇAMENTO');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(6, 2, 'PEDIDO', 'PEDIDO');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(7, 2, 'ORDEM DE SERVIÇOS', 'ORDEM DE SERVIÇOS');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(8, 2, 'CONDIÇÃO DE PAGAMENTO', 'CONDIÇÃO DE PAGAMENTO');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(9, 2, 'TIPO DE COBRANÇA', 'TIPO DE COBRANÇA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(10, 2, 'GRUPO FISCAL', 'GRUPO FISCAL');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(11, 2, 'NCMSH', 'NCMSH');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(12, 2, 'NATUREZA OPERAÇÃO(CFOP)', 'NATUREZA OPERAÇÃO(CFOP)');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(13, 2, 'SITUAÇÃO TRIBUTÁRIA', 'SITUAÇÃO TRIBUTÁRIA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(14, 2, 'TIPO DE NOTA FISCAL', 'TIPO DE NOTA FISCAL');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(15, 2, 'SÉRIE NOTAS', 'SÉRIE NOTAS');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(1, 3, 'CADASTRO LANÇAMENTO(AVULSO)', 'CADASTRO LANÇAMENTO(AVULSO)');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(2, 3, 'BAIXA CONTAS A RECEBER', 'BAIXA CONTAS A RECEBER');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(3, 3, 'BAIXA CONTAS A PAGAR', 'BAIXA CONTAS A PAGAR');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(4, 3, 'CADASTRO CONTA CRÉDITO', 'CADASTRO CONTA CRÉDITO');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(5, 3, 'CADASTRO CONTA DÉBITO', 'CADASTRO CONTA DÉBITO');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(6, 3, 'BALANCETE GERENCIAL', 'BALANCETE GERENCIAL');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(7, 3, 'CONTA FINANCEIRA', 'CONTA FINANCEIRA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(1, 4, 'REMESSA DE BOLETO', 'REMESSA DE BOLETO');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(2, 4, 'RETORNO DE BOLETO', 'RETORNO DE BOLETO');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(3, 4, 'CONSULTA RETORNO/REMESSA', 'CONSULTA RETORNO/REMESSA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(4, 4, 'IMPRESSÃO BOLETOS', 'IMPRESSÃO BOLETOS');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(1, 5, 'ORDEM DE COMPRA', 'ORDEM DE COMPRA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(2, 5, 'RELATÓRIO ORDEM DE COMPRA', 'RELATÓRIO ORDEM DE COMPRA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(1, 6, 'PRODUTO ENGENHARIA', 'PRODUTO ENGENHARIA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(2, 6, 'NOVA ENGENHARIA', 'NOVA ENGENHARIA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(1, 7, 'RELATÓRIO CLIENTES', 'RELATÓRIO CLIENTES');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(2, 7, 'RELATÓRIO PRODUTOS', 'RELATÓRIO PRODUTOS');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(3, 7, 'RELATÓRIO ORDEM DE SERVIÇOS', 'RELATÓRIO ORDEM DE SERVIÇOS');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(4, 7, 'RELATÓRIO ORÇAMENTOS', 'RELATÓRIO ORÇAMENTOS');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(5, 7, 'RELATÓRIO PEDIDOS', 'RELATÓRIO PEDIDOS');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(6, 7, 'RELATÓRIO ORDEM DE SERVIÇOS', 'RELATÓRIO ORDEM DE SERVIÇOS');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(7, 7, 'RELATÓRIO NOTA ENTRADA', 'RELATÓRIO NOTA ENTRADA');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(8, 7, 'RELATÓRIO NOTA FISCAL DE PRODUTOS(NFE)', 'RELATÓRIO NOTA FISCAL DE PRODUTOS(NFE)');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(9, 7, 'RELATÓRIO NOTA FISCAL DE SERVIÇOS(NFSE)', 'RELATÓRIO NOTA FISCAL DE SERVIÇOS(NFSE)');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(10, 7, 'RELATÓRIO REMESSAS ENVIADAS', 'RELATÓRIO REMESSAS ENVIADAS');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(11, 7, 'RELATÓRIO RETORNOS RECEBIDOS', 'RELATÓRIO RETORNOS RECEBIDOS');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(12, 7, 'RELATÓRIO CONTAS A PAGAR', 'RELATÓRIO CONTAS A PAGAR');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(13, 7, 'RELATÓRIO CONTAS A RECEBER', 'RELATÓRIO CONTAS A RECEBER');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(1, 8, 'Sistema', 'sistemas');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(2, 8, 'Menu', 'menu');
                INSERT INTO public.menu
                (mencodigo, siscodigo, mennome, mentabela)
                VALUES(3, 8, 'Usuário', 'usuario');
        ";

        // Executa a query de atualização
        //Executando atualização inicial...
        $this->getQuery()->query($sSql_atualizacao_inicial);
    }
}