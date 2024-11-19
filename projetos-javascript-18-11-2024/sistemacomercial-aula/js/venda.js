function carregaProduto(){
    console.log("aqui...");

    const idProduto = parseInt(document.querySelector("#produto_id").value);

    console.log("Carregando produto:" + idProduto);

    // Chamar a api e pegar os dados de produto
    const method = "GET";
    const rota = "produtos/" + idProduto;
    callApi(method, rota, function (data) {
        console.log("aqui...");

        document.querySelector("#quantidade").value = 1;
        document.querySelector("#descricao").value = data.descricao;
        document.querySelector("#precounitario").value = data.preco;

        // Calcular o total do item
        atualizaTotalItem();

        // Envia o foco para o campo de quantidade
        document.querySelector("#quantidade").focus();
    });
}

function atualizaTotalItem(){
    // calcula na tela e seta o foco no botão adicionar
    const quantidade = parseInt(document.querySelector("#quantidade").value);
    const precounitario = document.querySelector("#precounitario").value;
    const totalItem = quantidade * precounitario;
    document.querySelector("#total-item").value = totalItem;

    // seta o foco no botão de adicionar item
    document.querySelector("#btn-adicionar-item").focus();
}

function adicionarItem(){
    // Atualizar o estoque do item - ver por ultimo 

    // Adiciona o item na tela    
    const idProduto = parseInt(document.querySelector("#produto_id").value);
    const quantidade = document.querySelector("#quantidade").value;
    const descricao = document.querySelector("#descricao").value;
    const precounitario = document.querySelector("#precounitario").value;
    const totalitem = document.querySelector("#total-item").value;

    // Atualizar o total da venda 
    const totalAtual = parseFloat(document.querySelector("#totalvenda").value);
    const novoTotalVenda = totalAtual + parseFloat(totalitem);

    document.querySelector("#totalvenda").value = formataNum(novoTotalVenda);

    let bodyItem = document.querySelector("#tabela-item-venda");
    bodyItem.innerHTML += `<tr>
                                <td>${idProduto}</td>
                                <td class="text-lg-start">${descricao}</td>
                                <td>${quantidade}</td>
                                <td>${precounitario}</td>
                                <td>${totalitem}</td>
                            </tr>`;
}

function fecharModal() {
    const modal = document.querySelector("#dialogVenda");
    modal.close();
    modal.style.display = "none";
}

function incluirVenda() {
    const modal = document.querySelector("#dialogVenda");
    modal.showModal();
    modal.style.display = "block";

    // limpar o codigo do produto
    document.querySelector("#codigo").value = "";
    // seta a ação para INCLUSAO
    document.querySelector("#ACAO").value = "ACAO_INCLUSAO";

    // limpa os dados antes de incluir
    document.querySelector("#produto_id").value = "";
    document.querySelector("#descricao").value = "";
    document.querySelector("#precounitario").value = "";
    document.querySelector("#quantidade").value = "";
    document.querySelector("#total-item").value = "";

    const method = "GET";
    const rota = "vendas";
    let novoCodigo = 0;
    callApi(method, rota, function (data) {
        const proximoCodigo = parseInt(data.length) + 1;
        
        novoCodigo = parseInt(proximoCodigo);

        // Recebe os dados do servidor
        const aListaDados = data;

        // Percorrer o array e ver se nao tem um codigo maior
        aListaDados.forEach(function (data, key) {
            const codigo = data.id;
            if(codigo >= novoCodigo){
                novoCodigo = parseInt(codigo) + 1;
            }
        });

        console.log("Proximo codigo:" + novoCodigo);

        // Seta o proximo codigo na tela
        document.querySelector("#codigo").value = novoCodigo;
    });
}


function confirmarModalVenda() {
    // gravar a venda
    const idVenda     = document.querySelector("#codigo").value;
    const clicodigo   = document.querySelector("#cliente_id").value;
    const vendecodigo = document.querySelector("#vendedor_id").value;
    const condcodigo  = document.querySelector("#condpagto_id").value;
    const datavenda   = document.querySelector("#datavenda").value;
    const statusvenda = document.querySelector("#statusvenda").value;
    
    const acao = "ACAO_INCLUSAO";
    if (acao == "ACAO_INCLUSAO") {
        let body = {
            id:idVenda.toString()    
            ,clicodigo  
            ,vendecodigo
            ,condcodigo 
            ,datavenda  
            ,statusvenda
        };
        
        const method = "POST";
        const rota = "vendas";
        callApiPost(
            method,
            rota,
            function (data) {
                console.log("Venda gravada com sucesso!" + JSON.stringify(data));
                // executaConsulta();
                
                // gravar os itens da venda apos gravar a venda - fazer depois
                // falta esta parte

                fecharModal();
            },
            body
        );
    } else if (acao == "ACAO_ALTERACAO") {       
    }
}

function loadVendas(){
    if(validaSessaoSistema('PAGINA_DE_VENDAS')){
        // Carrega as vendas
        const method = "GET";
        const rota = "vendas";
        callApi(method, rota, function (data) {
            carregaTabelaConsulta(data);
        });
    }
}

function getDadosPessoa(clicodigo){
    const method = "GET";
    const rota = "pessoas/" + clicodigo;
    return callApi(method, rota);
}

function getDadosVendedor(vendecodigo){
    const method = "GET";
    const rota = "vendedor/" + vendecodigo;
    return callApi(method, rota);
}

function getDadosCondicaoPagamento(codigo){
    const method = "GET";
    const rota = "condicaopagamento/" + codigo;
    return callApi(method, rota);
}

async function carregaTabelaConsulta(aListaDados) {
    // Se não for array, coloca como array
    if (!Array.isArray(aListaDados)) {
        aListaDados = new Array(aListaDados);
    }

    const tabela = document.querySelector("#tabela-vendas");
    tabela.innerHTML = "";
    aListaDados.forEach(async function (data, key) {

        const codigo = data.id;
        
        // CHAMAR A API E PEGAR O NOME DO CLIENTE
        const dadosPessoa = await getDadosPessoa(data.clicodigo);
        const clicodigo = dadosPessoa.nome;

        // CHAMAR A API E PEGAR O NOME DO VENDEDOR
        const dadosVendedor = await getDadosVendedor(data.vendecodigo);
        const vendecodigo = dadosVendedor.nome;
        
        // CHAMAR A API E PEGAR A DESCRICAO DA CONDICAO DE PAGAMENTOS
        const dadosCondicaoPagamento = await getDadosCondicaoPagamento(data.condcodigo);
        const condcodigo = dadosCondicaoPagamento.nome;
        
        const datavenda = data.datavenda;
        const statusvenda = data.statusvenda;
        
        const acoes = getAcoes(codigo);

        tabela.innerHTML +=
            `
        <tr>
            <td class="text-center">` +
            codigo +
            `</td>
            <td style="text-align: left;">` +
            clicodigo +
            `</td>
            <td class="text-center" style="text-align: right;">` +
            vendecodigo +
            `</td>
            <td class="text-center">` +
            condcodigo +
            `</td> 
            <td class="text-center">` +
            datavenda +
            `</td> 
            <td class="text-center">` +
            statusvenda +
            `</td>           
            <td>` +
            acoes +
            `</td>
        </tr>
        `;
    });
}

function getAcoes(codigo) {
    return (
        `<div class="acoes text-center">
                <button class="btn btn-warning" onclick="alterarVenda(` +
        codigo +
        `)">Alterar</button>
                <button class="btn btn-danger" onclick="excluirVenda(` +
        codigo +
        `)">Excluir</button>        
                <button class="btn btn-info" onclick="detalharVenda(` +
        codigo +
        `)">Detalhar</button>
        </div>
    `
    );
}

function excluirVenda(codigo){
    const method = "DELETE";
    const rota = "vendas/" + codigo;
    callApi(method, rota, function (data) {
        loadVendas();
    });
}

function fecharModalItem() {
    const modal = document.querySelector("#dialogVendaItem");
    modal.close();
    modal.style.display = "none";
}

function detalharVenda(idVenda) {
    const modal = document.querySelector("#dialogVendaItem");
    modal.showModal();
    modal.style.display = "block";

    // Busca os dados da venda e preenche na tela
    // Inicia limpando os dados de venda
    getDadosVenda(idVenda);
}

function getDadosVenda(idVenda){
    // Inicia limpando os dados da venda
    document.querySelector("#codigo-item").value = "";
    document.querySelector("#cliente_id-item").value = "";
    document.querySelector("#vendedor_id-item").value = "";
    document.querySelector("#condpagto_id-item").value = "";
    document.querySelector("#datavenda-item").value = "";
    document.querySelector("#statusvenda-item").value = "";

    // Chamar a api e pegar os dados da venda atual
    const method = "GET";
    const rota = "vendas/" + idVenda;
    callApi(method, rota, function (data) {
        document.querySelector("#codigo-item").value = data.id;
        document.querySelector("#cliente_id-item").value = data.clicodigo;
        document.querySelector("#vendedor_id-item").value = data.vendecodigo;
        document.querySelector("#condpagto_id-item").value = data.condcodigo;
        document.querySelector("#datavenda-item").value = data.datavenda;
        document.querySelector("#statusvenda-item").value = data.statusvenda;    
        
        // set all elements disabled in the window
        document.querySelector("#cliente_id-item").setAttribute("disabled", true);
        document.querySelector("#cliente_id-item").setAttribute("disabled", true);
        document.querySelector("#vendedor_id-item").setAttribute("disabled", true);
        document.querySelector("#condpagto_id-item").setAttribute("disabled", true);
        document.querySelector("#datavenda-item").setAttribute("disabled", true);
        document.querySelector("#statusvenda-item").setAttribute("disabled", true);

        // load item
        let bodyItem = document.querySelector("#tabela-item-venda-detalhe");
        bodyItem.innerHTML = "";

        const method = "GET";
        const rota = "item?vencodigo=" + parseInt(idVenda);
        callApi(method, rota, function (data) {
            console.log("dados da venda retornados")                ;
            console.log(data);
            const aListaProdutos = data;
            aListaProdutos.forEach(async function (data, key) {
                // adicionando os itens da venda na tela
                bodyItem.innerHTML += `<tr>
                                            <td class="center">${data.id}</td>
                                            <td class="text-lg-start">${data.prodescricao}</td>
                                            <td class="center">${data.quantidade}</td>
                                            <td class="right">${data.valorunitario}</td>
                                            <td class="right">${data.valortotal}</td>
                                        </tr>`;
            });
        }); 
    });   
}