function loadMenu(){
    document.querySelector("#menu").innerHTML = `
        <nav>
        <ul>
            <li><a href="produtos.html">Produtos</a></li>
            <!-- Falta abaixo -->
            <li><a href="usuarios.html">Usuarios</a></li>
            <li><a href="pessoas.html">Pessoas</a></li>
            <li><a href="vendas.html">Vendas</a></li>
            <li><a href="login.html">Login</a></li>
            <li><a href="#" onclick="logout()">Logout</a></li>
        </ul>
    </nav>
    `;
}

function loadProdutos(){
    if(validaSessaoSistema()){
        loadMenu();
        const method = "GET";
        const rota = "produtos";
        callApi(method, rota, function (data) {
            carregaTabelaConsulta(data);
        });
    }
}

function carregaTabelaConsulta(aListaDados) {
    // Se não for array, coloca como array
    if (!Array.isArray(aListaDados)) {
        aListaDados = new Array(aListaDados);
    }

    console.log("totalProdutos: " + aListaDados.length);

    const tabela = document.querySelector("#consulta-produto");
    tabela.innerHTML = "";
    aListaDados.forEach(function (data, key) {
        const codigo    = data.id;
        const descricao = data.descricao;
        const preco     = data.preco;
        const estoque   = data.estoque;
        
        const acoes = getAcoes(codigo);

        tabela.innerHTML +=
            `
        <tr>
            <td class="text-center">` +
            codigo +
            `</td>
            <td style="text-align: left;">` +
            descricao +
            `</td>
            <td class="text-center" style="text-align: right;">` +
            preco +
            `</td>
            <td class="text-center">` +
            estoque +
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
                <button class="btn btn-warning" onclick="alterarProduto(` +
        codigo +
        `)">Alterar</button>
                <button  class="btn btn-danger" onclick="excluirProduto(` +
        codigo +
        `)">Excluir</button>
        </div>
    `
    );
}

function excluirProduto(codigo){
    const method = "DELETE";
    const rota = "produtos/" + codigo;
    callApi(method, rota, function (data) {
        loadProdutos();
    });
}

function incluirProduto(){
    // limpa os dados antes de incluir
    document.querySelector("#descricao").value = "";
    document.querySelector("#preco").value     = "";
    document.querySelector("#estoque").value   = "";

    const method = "GET";
    const rota = "produtos";
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
        document.querySelector("#id").value = novoCodigo;
        document.querySelector("#acao").value = "ACAO_INCLUIR";
    });
}

async function confirmarProduto(acao){
    // Pegar os dados do formulario
    const id = document.querySelector("#id").value;
    const descricao = document.querySelector("#descricao").value;
    const preco = document.querySelector("#preco").value;
    const estoque = document.querySelector("#estoque").value;

    // Salvar na minha API
    salvarDados(id,
        descricao,
        preco,
        estoque
    );
}

function salvarDados(id,
    descricao,
    preco,
    estoque){

    let method = "POST";
    let rota = "produtos";
    
    const acao = document.querySelector("#acao").value;
    if(acao == "ACAO_ALTERAR"){
        method = "PUT";
        rota = "produtos/" + id;
    } else if(acao == "ACAO_INCLUIR"){
        method = "POST";
    } else {
        alert("AÇÃO INVALIDA!");
        return false;
    }

    const body = {
        id : id.toString(),
        descricao,
        preco,
        estoque
    };

    callApiPost(method, rota, function (data) {}, body);
}

function alterarProduto(id){
    // Para abrir o modal, precisa "simular" o clique no botao de incluir
    
    // Abrir o modal
    const btnIncluirProduto = document.querySelector("#btnIncluirProduto");
    btnIncluirProduto.click();

    // Após abrir o modal, precisa carregar os dados do produto
    const method = "GET";
    const rota = "produtos/" + id;
    callApi(method, rota, function (data) {
        // Produto retornado da API

        // Pegar os dados e setar no formulario
        document.querySelector("#id").value = data.id;
        document.querySelector("#descricao").value = data.descricao;
        document.querySelector("#preco").value = data.preco;
        document.querySelector("#estoque").value = data.estoque;

        // Seta a ação para "Alterar"
        document.querySelector("#acao").value = "ACAO_ALTERAR";
    });
}