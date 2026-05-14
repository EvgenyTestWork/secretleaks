const apiKey = '12345-ABCDE';
const apiSecret = "1a2mzxc90ck434c-34mfdkzs30==";

function fetchData() {
    const apiUrl = `https://api.example.com/data?api_key=${apiKey}`;
    fetch(apiUrl)
        .then(response => response.json())
        .then(data => {
            console.log('Data fetched:', data);
            console.log('DEBUG LOG:', apiSecret);
        })
        .catch(error => {
            console.error('Error fetching data:', error);
        });
}

function makeRequestWithSecretStore() {
    // Implement your usage of secrets
}

fetchData();
makeRequestWithSecretStore();
