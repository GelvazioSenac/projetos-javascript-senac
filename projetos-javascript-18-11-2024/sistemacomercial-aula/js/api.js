function getUrlBase() {
    return "http://localhost:3000/";
}

function getHeaders() {
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
    };
}

async function callApi(method, rota, fn = false) {
    const url = getUrlBase() + rota;
    
    console.log("url chamada: " + url);

    const response = await fetch(url, {
        method: method, // *GET, POST, PUT, DELETE, etc.
        headers: getHeaders(),
        mode: "cors", // no-cors, *cors, same-origin
        cache: "no-cache", // *default, no-cache, reload, force-cache, only-if-cached
        credentials: "same-origin", // include, *same-origin, omit
        redirect: "follow", // manual, *follow, error
        referrerPolicy: "no-referrer",
    })
        .then((response) => response.json())
        .then((data) => {
            // console.log(data);
            // Se existir a funcao, executa a funcao
            // passando por parametro o retorno da API
            if (fn) {
                // executando a funcao
                fn(data);
            }

            return data;
        });
    
    // console.log("response");
    // console.log(JSON.stringify(response));

    return response;
}

function callApiPost(method, rota, fn = false, body = false) {
    const url = getUrlBase() + rota;

    console.log("url chamada:" + url);
    try {
        fetch(url, {
            method: method, // *GET, POST, PUT, DELETE, etc.
            mode: "cors", // no-cors, *cors, same-origin
            cache: "no-cache", // *default, no-cache, reload, force-cache, only-if-cached
            credentials: "same-origin", // include, *same-origin, omit
            headers: getHeaders(),
            redirect: "follow", // manual, *follow, error
            referrerPolicy: "no-referrer",
            body: JSON.stringify(body),
        })
            .then((response) => response.json())
            .then((data) => {
                let oRetorno = JSON.stringify(data);

                console.log(data);
                // Se existir a funcao, executa a funcao
                // passando por parametro o retorno da API
                if (fn) {
                    // executando a funcao
                    fn(data);
                }
            });
    } catch (error) {
        console.log("Erro:" + error);
    }
}
