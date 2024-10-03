const http = require("http");
const app = require("./app");
const server  = http.createServer(app);
const user = require('./models/user');

const port = process.env.port || API_PORT;
console.log('port',port);
const routes = require('./routes/ApiRoutes');    
routes(app);

app.use(function(req,res){
    res.status(404).send({url: req.originalUrl + 'Not FOund'})
})

// Server Listning
server.listen(port,()=>{
    console.log(`server running on port ${port}`)
})

