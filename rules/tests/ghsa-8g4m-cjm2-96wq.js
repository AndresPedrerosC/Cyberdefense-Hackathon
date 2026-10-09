const vm = require('vm')
// ruleid: ghsa-8g4m-cjm2-96wq-notevil-sandbox-escape
const safeEval = require('notevil')

function b2bOrder (req, res) {
  const sandbox = { safeEval, orderLinesData: req.body.orderLinesData }
  vm.createContext(sandbox)
  vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
  res.json({ ok: true })
}

module.exports = { b2bOrder }
