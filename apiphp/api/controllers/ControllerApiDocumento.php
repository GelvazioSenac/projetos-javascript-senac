<?php
//require_once 'api/lib/d4sign/vendor/d4sign/d4sign-php/sdk/vendor/autoload.php';

use \Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
//use D4sign\Client;

/**
 * Chamada da api Documentos
 *
 * User: Gelvazio Camargo
 * Date: 26/05/2021
 * Time: 18:40
 */

require_once("ControllerApiBase.php");
class ControllerApiDocumento extends ControllerApiBase {

    public function getDocumentos(Request $request, Response $response, array $args) {
        $sSql = "SELECT * FROM documentos ORDER BY 1";
        $aDados = $this->getQuery()->selectAll($sSql);
        return $response->withJson($aDados, 200);
    }

    public function assinaDocumento(Request $request, Response $response, array $args) {
        $fileName = "DOCUMENTO_TESTE-9EE167D9-C869-4E05-B6F3-2B8391D4E540";
//        $token = "live_11334eccb0140f9cc737373737373d66eb9264fb1cdc022da3acb08a31c271c7";
//        $crypt = "live_wqe313_2JNnkvCAdadadadadLkCKR0UBs3";
//        $uuid_safe = "rere-ttt-4841-33-33333";
//        "uuid_safe": "ded472b5-0f98-4841-8b53-52698acb0d81",

        $token     = "";
        $crypt     = "";
        $uuid_safe = " ";
        
        // Ambiente	                 Endpoint	                          Validade jurídica
        // Produção	                 https://secure.d4sign.com.br/api/v1  true
        // Desenvolvimento (SandBox) http://demo.d4sign.com.br/api/v1	  false
        
        $cofre = "TIDAS_TECNOLOGIA";
        $listacofres = "Ex.: https://secure.d4sign.com.br/api/v1/safes?tokenAPI={SEU-TOKEN}&cryptKey={SEU-CRYPT-KEY}";
        
        // documentacao doc4sign
        // http://docapi.d4sign.com.br/
        try {
            $client = new Client();
            $client->setAccessToken($token);
            $client->setCryptKey($crypt);
            $tipos = array(1);

            $ok = false;
            $aListaErro = array();
            foreach ($tipos as $tipo) {

                $pdf = "PEGA PDF DA PASTA TEMP";

                $path = "temp/".$fileName.".pdf";

                file_put_contents($path, $pdf);

                $id_doc = $client->documents->upload($uuid_safe, $path);

                if ($id_doc != "") {
                    $signers = array();
                    $dadosContrato = array();
                    $dadosContrato[0] = 0;
                    $dadosContrato[1] = '';
                    $dadosContrato[2] = 'GELVAZIODEV@GMAIL.COM';
                    $dadosContrato[3] = 5;
                    $dadosContrato[4] = '0';
                    $dadosContrato = array($dadosContrato);
                    
                    foreach ($dadosContrato as $dadoContrato) {
                        $email = $dadoContrato[2];
                        $certificado = $dadoContrato[4];

                        if (intval($dadoContrato[3]) > 0) {
                            $papel = $dadoContrato[3];

                            $signer = array(
                                'email'                 => $email,
                                'act'                   => $papel,
                                'foreign'               => '0',
                                'certificadoicpbr'      => $certificado,
                                'assinatura_presencial' => '0',
                                'embed_methodauth'      => 'email',
                                'embed_smsnumber'       => '');

                            array_push($signers, $signer);
                        }
                    }

                    $uuid = $id_doc->uuid;

                    $signatario = $client->documents->createList($uuid, $signers);
                    if ($signatario->message != "") {
                        $existeErro = false;
                        foreach ($signatario->message as $mensagem) {
                            if(isset($mensagem->error)){
                                if (intval(isset($mensagem->error) == 1)) {
                                    $existeErro = true;
                                    array_push($aListaErro, $mensagem->status . ' <br>Log erro: <br>' . json_encode($mensagem));
                                }
                            }
                        }
                        if($existeErro){
                            continue;
                        }

                        $workflow = 1;
                        if (count($signatario->message) == 1) {
                            $workflow = 0;
                        }

                        // Enviar Documento para assinatura
                        $message = 'Prezado(a), segue o documento eletrônico para assinatura.';
                        
                        $skip_email = 0; //Os signatários serão avisados

                        $doc = $client->documents->sendToSigner($uuid, $message, $workflow, $skip_email);

                        if ($doc != "") {
                            $ok = true;
                        }
                    }
                }
            }

            if(count($aListaErro)){
                $mensagemErro = "ERRO:Erro ao gerar lista de assinantes!<br>" . implode(',', $aListaErro);
                
                Utils::enviaMensagemSlack("Erro ao assinar Documento!", $mensagemErro);

                return $response->withJson($aDados = json_encode(array("Erro" => $mensagemErro)), 200);                
            }

            if ($ok) {
                return $response->withJson($aDados = json_encode(array("ok" => true)), 200);
            }
        } catch (Exception $e) {
            $mensagemErro = "ERRO: Ocorreu o seguinte erro ao assinar o documento: <br><pre>".$e->getMessage()."</pre>";

            Utils::enviaMensagemSlack("Erro ao assinar Documento!", $mensagemErro);
            
            return $response->withJson($aDados = json_encode(array("Erro" => $mensagem)), 200);
        }

        return $response->withJson(json_encode(array("Sucesso" => true)));
    }
}