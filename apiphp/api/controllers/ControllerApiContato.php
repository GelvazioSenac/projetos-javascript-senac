<?php
use \Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;

/**
 * Chamada da api Contato
 *
 * User: Gelvazio Camargo
 * Date: 20/05/2021
 * Time: 18:40
 */
require_once("ControllerApiBase.php");
class ControllerApiContato extends ControllerApiBase {

    public function listaContatos(Request $request, Response $response, array $args) {
        $sSql = "SELECT * FROM contacts ORDER BY 1 desc";
        $aDados = $this->getQuery()->selectAll($sSql);
        $xDados = array();
        foreach ($aDados as $sDados){
            array_push($xDados, $sDados);
        }

        $total = $this->getQuery()->select("select count(*) as total from contacts");
        $total = intval($total["total"]);
        
        $xDados = array(
            "success" => true,
            "total" => $total,
            "contatos" => $xDados
        );
        return $response->withJson($xDados, 200);
    }
    
    public function criaContato(Request $request, Response $response, array $args) {
        $sql_id_seq = "select NEXTVAL('contacts_id_seq') as id";

        $oDados = $this->getQuery()->select($sql_id_seq);
        
        $id = intval($oDados["id"]);

        $oContato = $this->getModelFromRequest($request);
        $email = $oContato->email;
        $name  = $oContato->name;
        $phone = $oContato->phone;
        
        $sSqlInsert = "INSERT INTO contacts (id,email,name,phone) values ($id,'$email','$name','$phone')";

        $this->getQuery()->query($sSqlInsert);

        $xDados = array(
            "success" => true,
            "id" => $id,
            "contatos" => json_encode($oContato)
        );
        
        return $response->withJson($xDados, 200);
    }   
    
    public function atualizaContato(Request $request, Response $response, array $args) {
        $oContato = $this->getModelFromRequest($request);
        $email = $oContato->email;
        $name  = $oContato->name;
        $phone = $oContato->phone;
        $id    = $oContato->id;
     
        $sql_update = "update contacts set email = '$email',
                            name = '$name',
                            phone = '$phone'
                            where id = $id";
        
        $this->getQuery()->query($sql_update);
    
        $xDados = array(
            "success" => true,
            "contatos"=> json_encode($oContato)
        );

        return $response->withJson($xDados, 200);
    } 
    
    public function deletaContato(Request $request, Response $response, array $args) {
        $oContato = $this->getModelFromRequest($request);
        $id = intval($oContato->id);
        
        $sSql = "DELETE FROM contacts WHERE id = $id";
        
        $this->getQuery()->query($sSql);
        
        $xDados = array(
            "success" => true
        );
        return $response->withJson($xDados, 200);
    }
    
    private function getModelFromRequest($request){
        $aDados = json_encode($request->getParsedBody());

        $aDadosDecode = json_decode($aDados);

        $oContato = json_decode($aDadosDecode->contatos);
        return $oContato;
    }
}