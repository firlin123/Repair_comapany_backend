const routes = {
  '/api/login': [login, 'application/json'],
  '/api/register': [register, 'application/json'],
  '/api/me': [me],
  '/api/logout': [logout],
  '/api/newOrder': [newOrder, 'application/json'],
  '/api/myOrders': [myOrders],
  '/api/worker/orders': [workerOrders],
  '/api/worker/orderDone': [workerOrderDone, 'application/json'],
  '/api/worker/orderAccept': [workerOrderAccept, 'application/json']
};
const sessionExpirationTime = 3600;

export default {
  async fetch(request, env) {
      return await handle(request, env)
  },
}

async function handle(request, env) {
  if (request.method === "OPTIONS") {
      return await handleOptions(request);
  } else {
      let { pathname } = new URL(request.url);;
      const handler = routes[pathname];
      if (handler == null) {
          return errorJsonResponce('Path "' + pathname + '" not found', 404, "Not Found");
      }
      else {
          try {
              const contentType = request.headers.get('Content-Type') ?? '';
              var pass = (handler.length > 1) ? contentType.includes(handler[1]) : true;
              if (pass) {
                  return await handler[0](request, env);
              }
              else return errorJsonResponce('Not a "' + handler[1] + '" request');
          }
          catch (e) {
              return errorJsonResponce('Uncaught exception: ' + e);
          }
      }
  }
}

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
}

async function handleOptions(request) {
  if (request.headers.get("Origin") !== null &&
      request.headers.get("Access-Control-Request-Method") !== null &&
      request.headers.get("Access-Control-Request-Headers") !== null) {
      // Handle CORS pre-flight request.
      return new Response(null, {
          headers: corsHeaders
      })
  } else {
      // Handle standard OPTIONS request.
      return new Response(null, {
          headers: {
              "Allow": "GET, HEAD, POST, OPTIONS",
          }
      })
  }
}

function jsonTryParse(json) {
  try {
      return JSON.parse(json);
  }
  catch (e) {
      return undefined;
  }
}

function userCopy(user) {
  return {
      email: user.email,
      name: user.name,
      phone: user.phone,
      emailValidationRequired: user.emailValidationRequired,
      role: user.role
  };
}

function orderCopy(order, noStatus = false) {
  return noStatus ? {
      id: order.id,
      item: order.item,
      defect: order.defect,
      time: order.time,
  } : {
      id: order.id,
      item: order.item,
      defect: order.defect,
      time: order.time,
      status: order.status
  }
}

async function authCheck(request, env) {
  const authorization = request.headers.get('Authorization');
  if (typeof authorization === 'string') {
      return (await env.RepairSessions.get(authorization)) ?? false;
  }
  return false;
}

async function incrementId(db, key) {
  const v = JSON.parse(await db.get(key) ?? '0');
  await db.put(key, (v + 1).toString());
  return v;
}

async function workerOrderAccept(request, env) {
  const email = await authCheck(request, env);
  if (!email) {
      return errorJsonResponce('Invalid or empty token', 401, 'Unauthorized');
  }
  const body = jsonTryParse(await request.text());
  if (typeof body !== 'object') {
      return errorJsonResponce('Invalid json');
  }
  const user = jsonTryParse(await env.RepairUsers.get(email));
  if (user == null) {
      return errorJsonResponce('User not found');
  }
  if (user.role !== 'worker' && user.role !== 'admin') {
      return errorJsonResponce('Only admin or worker can access this', 403, 'Forbidden');
  }
  if (body.id == null) {
      return errorJsonResponce('Id is null');
  }
  if (typeof body.id !== 'number') {
      return errorJsonResponce('Id is not number');
  }
  const order = jsonTryParse(await env.RepairOrders.get(body.id.toString()));
  if (order == null) {
      return errorJsonResponce('Order not found');
  }
  if (order.status !== 'new') {
      return errorJsonResponce('Order status is not new');
  }
  order.status = 'open';
  order.worker = email;
  await env.RepairOrders.put(order.id.toString(), JSON.stringify(order));
  const orderC = orderCopy(order, true);
  const customer = jsonTryParse(await env.RepairUsers.get(order.customer)) ?? {};
  if (typeof customer.name === 'string' && customer.name !== '') {
      orderC.customerName = customer.name;
  }
  else orderC.customerName = 'No name';
  if (typeof customer.phone === 'string' && customer.phone !== '') {
      orderC.customerPhone = customer.phone + '';
  }
  else orderC.customerName = 'No phone';
  return jsonResponce(orderC);
}

async function workerOrderDone(request, env) {
  const email = await authCheck(request, env);
  if (!email) {
      return errorJsonResponce('Invalid or empty token', 401, 'Unauthorized');
  }
  const body = jsonTryParse(await request.text());
  if (typeof body !== 'object') {
      return errorJsonResponce('Invalid json');
  }
  const user = jsonTryParse(await env.RepairUsers.get(email));
  if (user == null) {
      return errorJsonResponce('User not found');
  }
  if (user.role !== 'worker' && user.role !== 'admin') {
      return errorJsonResponce('Only admin or worker can access this', 403, 'Forbidden');
  }
  if (body.id == null) {
      return errorJsonResponce('Id is null');
  }
  if (typeof body.id !== 'number') {
      return errorJsonResponce('Id is not number');
  }
  if (body.cause == null) {
      return errorJsonResponce('Cause is null');
  }
  if (typeof body.cause !== 'string') {
      return errorJsonResponce('Cause is not string');
  }
  if (body.price == null) {
      return errorJsonResponce('Price is null');
  }
  if (typeof body.price !== 'number') {
      return errorJsonResponce('Price is not number');
  }
  const order = jsonTryParse(await env.RepairOrders.get(body.id.toString()));
  if (order == null) {
      return errorJsonResponce('Order not found');
  }
  if (order.status !== 'open') {
      return errorJsonResponce('Order status is not open');
  }
  const customer = jsonTryParse(await env.RepairUsers.get(order.customer));
  if (customer == null) {
      return errorJsonResponce('Customer not found');
  }
  (customer.orders?.find?.(o => o.id === order.id) ?? {}).done = true;
  await env.RepairUsers.put(order.customer, JSON.stringify(customer))
  await env.RepairOrders.delete(order.id.toString());
  order.cause = body.cause;
  order.price = body.price;
  order.status = 'done';
  order.doneTime = Date.now();
  await env.RepairOrdersDone.put(order.id.toString(), JSON.stringify(order));
  return jsonResponce('OK');
}


async function workerOrders(request, env) {
  const email = await authCheck(request, env);
  if (!email) {
      return errorJsonResponce('Invalid or empty token', 401, 'Unauthorized');
  }
  const user = jsonTryParse(await env.RepairUsers.get(email));
  if (user == null) {
      return errorJsonResponce('User not found');
  }
  if (user.role !== 'worker' && user.role !== 'admin') {
      return errorJsonResponce('Only admin or worker can access this', 403, 'Forbidden');
  }
  const myOrders = [];
  const newOrders = [];
  const orderCustomers = {};
  const allOrders = {};
  const orderKeys = ((await env.RepairOrders.list())?.keys) ?? [];
  for (const key of orderKeys) {
      const order = jsonTryParse(await env.RepairOrders.get(key.name));
      if (order != null) {
          allOrders[key.name] = order;
      }
  }
  for (var order of Object.values(allOrders)) {
      console.log(order.status);
      if (order.status === 'new') newOrders.push(orderCopy(order, true));
      else if (order.status === 'open' && order.worker === email) {
          const orderC = orderCopy(order, true);
          if (orderCustomers[order.customer] == null) {
              orderCustomers[order.customer] = jsonTryParse(await env.RepairUsers.get(order.customer)) ?? {};
          }
          if (typeof orderCustomers[order.customer].name === 'string' && orderCustomers[order.customer].name !== '') {
              orderC.customerName = orderCustomers[order.customer].name;
          }
          else orderC.customerName = 'No name';
          if (typeof orderCustomers[order.customer].phone === 'string' && orderCustomers[order.customer].phone !== '') {
              orderC.customerPhone = orderCustomers[order.customer].phone + '';
          }
          else orderC.customerName = 'No phone';
          myOrders.push(orderC);
      }
  }
  return jsonResponce({ newOrders, myOrders });
}

async function myOrders(request, env) {
  const email = await authCheck(request, env);
  if (!email) {
      return errorJsonResponce('Invalid or empty token', 401, 'Unauthorized');
  }
  const user = jsonTryParse(await env.RepairUsers.get(email));
  if (user == null) {
      return errorJsonResponce('User not found');
  }
  const orders = [];
  const doneOrders = [];
  const orderWorkers = {};
  for (const orderInfo of (user.orders ?? [])) {
      const order = jsonTryParse(await (orderInfo.done ? env.RepairOrdersDone : env.RepairOrders).get(orderInfo.id.toString()));

      if (order != null) {
          const orderC = orderCopy(order);
          if (typeof order.worker === 'string' && order.worker !== '') {
              if (orderWorkers[order.worker] == null) {
                  orderWorkers[order.worker] = jsonTryParse(await env.RepairUsers.get(order.worker)) ?? {};
              }
              if (typeof orderWorkers[order.worker].name === 'string' && orderWorkers[order.worker].name !== '') {
                  orderC.workerName = orderWorkers[order.worker].name + '';
              }
          }
          if (orderInfo.done) {
              orderC.cause = order.cause ?? '';
              if (orderC.cause === '') orderC.cause = 'No cause';
              orderC.price = order.price ?? 0;
              orderC.doneTime = order.doneTime ?? Date.now();
              doneOrders.push(orderC);
          }
          else orders.push(orderC);
      }
  }
  return jsonResponce({ orders, doneOrders });
}

async function newOrder(request, env) {
  const email = await authCheck(request, env);
  if (!email) {
      return errorJsonResponce('Invalid or empty token', 401, 'Unauthorized');
  }
  const user = jsonTryParse(await env.RepairUsers.get(email));
  if (user == null) {
      return errorJsonResponce('User not found');
  }
  const body = jsonTryParse(await request.text());
  if (typeof body !== 'object') {
      return errorJsonResponce('Invalid json');
  }
  if (body.item == null) {
      return errorJsonResponce('Item is null');
  }
  if (typeof body.item !== 'string') {
      return errorJsonResponce('Item is not string');
  }
  //if (!(allowedItems.includes(body.item))) {
  //    return errorJsonResponce('Invalid item');
  //}
  if (body.defect == null) {
      return errorJsonResponce('Defect is null');
  }
  if (typeof body.defect !== 'string') {
      return errorJsonResponce('Defect is not string');
  }
  const id = await incrementId(env.RepairOrders, 'last_order');
  const order = {
      id,
      customer: email,
      item: body.item,
      defect: body.defect,
      time: Date.now(),
      status: 'new'
  };
  (user.orders = user.orders ?? []).push({ done: false, id });
  await env.RepairOrders.put(id, JSON.stringify(order));
  await env.RepairUsers.put(email, JSON.stringify(user));
  return jsonResponce('OK');
}

async function logout(request, env) {
  const authorization = request.headers.get('Authorization');
  if (typeof authorization === 'string') {
      try { (await env.RepairSessions.delete(authorization)) } catch (e) { };
  }
  return jsonResponce('OK');
}

async function me(request, env) {
  const email = await authCheck(request, env);
  if (!email) {
      return errorJsonResponce('Invalid or empty token', 401, 'Unauthorized');
  }
  const user = jsonTryParse(await env.RepairUsers.get(email));
  if (user == null) {
      return errorJsonResponce('User not found');
  }
  return jsonResponce(userCopy(user));
}

async function login(request, env) {
  if (await authCheck(request, env)) {
      return errorJsonResponce('Already authorized');
  }
  const body = jsonTryParse(await request.text());
  if (typeof body !== 'object') {
      return errorJsonResponce('Invalid json');
  }
  if (typeof body.email !== 'string') {
      return errorJsonResponce('Invalid email or password');
  }
  body.email = body.email.toLocaleLowerCase();
  const user = jsonTryParse(await env.RepairUsers.get(body.email));
  if (user == null) {
      return errorJsonResponce('Invalid email or password');
  }
  if (user.password !== await sha256(body.password)) {
      return errorJsonResponce('Invalid email or password');
  }
  const authToken = await sha256(Date.now() + crypto.randomUUID()); //crypto.randomUUID();
  const result = { token: authToken, role: user.role };
  if (body.rememberMe === true) {
      await env.RepairSessions.put(authToken, body.email);
  }
  else {
      await env.RepairSessions.put(authToken, body.email, { expirationTtl: sessionExpirationTime });
      result.expirationTtl = sessionExpirationTime;
  }
  return jsonResponce(result);
}

const emailRegex = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"|,.<>\/?])[A-Za-z\d!@#$%^&*()_+\-=\[\]{};':"|,.<>\/?]{8,255}$/;
const phoneRegex = /^(\s*)?(\+)?([- _():=+]?\d[- _():=+]?){10,14}(\s*)?$/;
async function register(request, env) {
  if (await authCheck(request, env)) {
      return errorJsonResponce('Already authorized');
  }
  const body = jsonTryParse(await request.text());
  if (typeof body !== 'object') {
      return errorJsonResponce('Invalid json');
  }
  if (body.email == null) {
      return errorJsonResponce('Email is null');
  }
  if (typeof body.email !== 'string') {
      return errorJsonResponce('Email is not string');
  }
  body.email = body.email.toLocaleLowerCase();
  if (body.email.match(emailRegex) == null) {
      return errorJsonResponce('Invalid email address');
  }
  if (body.password == null) {
      return errorJsonResponce('Password is null');
  }
  if (typeof body.password !== 'string') {
      return errorJsonResponce('Password is not string');
  }
  if (body.password.match(passwordRegex) == null) {
      return errorJsonResponce('Invalid password');
  }
  if (body.phone == null) {
      return errorJsonResponce('Phone is null');
  }
  if (typeof body.phone !== 'string') {
      return errorJsonResponce('Phone is not string');
  }
  if (body.phone.match(phoneRegex) == null) {
      return errorJsonResponce('Invalid phone');
  }
  if (await env.RepairUsers.get(body.email) != null) {
      return errorJsonResponce('User with this email already exists');
  }
  const user = {
      email: body.email,
      name: body.name ?? 'No name',
      phone: body.phone,
      password: await sha256(body.password),
      emailValidationRequired: true,
      role: 'user'
  };
  const authToken = await sha256(Date.now() + crypto.randomUUID()); //crypto.randomUUID();
  await env.RepairSessions.put(authToken, body.email);
  await env.RepairUsers.put(body.email, JSON.stringify(user));
  return jsonResponce({ token: authToken, role: 'user' });
}

function errorJsonResponce(reason, status = 400, statusText = 'Bad Request') {
  return jsonResponce({ 'error': reason }, status, statusText);
}

function jsonResponce(obj, status = 200, statusText = 'OK') {
  return generalResponce(JSON.stringify(obj), 'application/json', status, statusText);
}

function generalResponce(text, contentType, status = 200, statusText = 'OK') {
  return new Response(text, { 'headers': { 'access-control-allow-origin': '*', 'content-type': contentType }, status, statusText });
}

async function sha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder("utf-8").encode(str));
  return Array.prototype.map.call(new Uint8Array(buf), x => (('00' + x.toString(16)).slice(-2))).join('');
}