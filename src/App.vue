<script setup>
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'

const splitCsv = (value) => {
  if (!value) return []
  if (Array.isArray(value)) return value.filter(Boolean)
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
}

const toCsv = (value) => {
  if (!value) return ''
  return Array.isArray(value) ? value.join(', ') : String(value)
}

const parseJsonSafe = (value, fallback = {}) => {
  try {
    return JSON.parse(value)
  } catch {
    return fallback
  }
}

const createDnsServer = () => ({
  tag: '',
  address: '',
  detour: '',
  address_resolver: '',
  strategy: 'ipv4_only',
})

const createDnsRule = () => ({
  outbound: '',
  server: '',
  domain_suffix: '',
  domain_keyword: '',
  geosite: '',
  geoip: '',
  clash_mode: '',
})

const createInbound = () => ({
  type: 'mixed',
  tag: '',
  listen: '0.0.0.0',
  listen_port: 1080,
  sniff: true,
  sniff_override_destination: true,
  users_json: '[]',
})

const createOutbound = () => ({
  type: 'direct',
  tag: '',
  server: '',
  server_port: 443,
  uuid: '',
  password: '',
  method: '2022-blake3-aes-128-gcm',
  tls: false,
  multiplex: false,
})

const createRouteRule = () => ({
  outbound: '',
  protocol: '',
  domain_suffix: '',
  domain_keyword: '',
  geosite: '',
  geoip: '',
  ip_cidr: '',
  port: '',
  network: '',
  package_name: '',
  process_name: '',
  clash_mode: '',
})

const createRuleSet = () => ({
  tag: '',
  type: 'remote',
  format: 'binary',
  url: '',
  path: '',
  download_detour: '',
  update_interval: '1d',
})

const createDefaultModel = () => ({
  log: {
    level: 'info',
    timestamp: true,
    disabled: false,
  },
  dns: {
    strategy: 'ipv4_only',
    final: 'dns-remote',
    servers: [
      {
        ...createDnsServer(),
        tag: 'dns-remote',
        address: 'https://1.1.1.1/dns-query',
      },
      {
        ...createDnsServer(),
        tag: 'dns-local',
        address: 'local',
      },
    ],
    rules: [
      {
        ...createDnsRule(),
        geosite: 'cn',
        server: 'dns-local',
      },
      {
        ...createDnsRule(),
        server: 'dns-remote',
      },
    ],
  },
  inbounds: [
    {
      ...createInbound(),
      type: 'mixed',
      tag: 'mixed-in',
      listen_port: 2080,
    },
  ],
  outbounds: [
    {
      ...createOutbound(),
      type: 'selector',
      tag: 'select',
    },
    {
      ...createOutbound(),
      type: 'urltest',
      tag: 'auto',
    },
    {
      ...createOutbound(),
      type: 'direct',
      tag: 'direct',
    },
    {
      ...createOutbound(),
      type: 'block',
      tag: 'block',
    },
  ],
  route: {
    auto_detect_interface: true,
    final: 'select',
    rules: [
      {
        ...createRouteRule(),
        geosite: 'category-ads-all',
        outbound: 'block',
      },
      {
        ...createRouteRule(),
        geoip: 'cn',
        outbound: 'direct',
      },
    ],
    rule_set: [createRuleSet()],
  },
  experimental: {
    cache_file: {
      enabled: true,
      path: 'cache.db',
    },
    clash_api: {
      external_controller: '127.0.0.1:9090',
      secret: '',
      default_mode: 'Rule',
      external_ui: '',
    },
  },
  ntp: {
    enabled: false,
    server: 'time.apple.com',
    server_port: 123,
  },
  extra_json: '{}',
})

const model = ref(createDefaultModel())
const importText = ref('')
const activeTab = ref('basic')

const outboundTags = computed(() => model.value.outbounds.map((item) => item.tag).filter(Boolean))
const dnsTags = computed(() => model.value.dns.servers.map((item) => item.tag).filter(Boolean))

const buildOutboundPayload = (outbound) => {
  const payload = {
    type: outbound.type,
    tag: outbound.tag,
  }

  if (['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2'].includes(outbound.type)) {
    payload.server = outbound.server
    payload.server_port = Number(outbound.server_port || 443)
  }

  if (['vless', 'vmess'].includes(outbound.type) && outbound.uuid) {
    payload.uuid = outbound.uuid
  }

  if (['trojan', 'shadowsocks', 'hysteria2'].includes(outbound.type) && outbound.password) {
    payload.password = outbound.password
  }

  if (outbound.type === 'shadowsocks') {
    payload.method = outbound.method
  }

  if (['selector', 'urltest'].includes(outbound.type)) {
    payload.outbounds = outbound.outbounds?.length ? splitCsv(outbound.outbounds) : ['direct']
  }

  if (outbound.type === 'urltest') {
    payload.url = outbound.url || 'https://www.gstatic.com/generate_204'
    payload.interval = outbound.interval || '3m'
  }

  if (outbound.tls && ['vless', 'vmess', 'trojan', 'hysteria2'].includes(outbound.type)) {
    payload.tls = { enabled: true }
  }

  if (outbound.multiplex) {
    payload.multiplex = { enabled: true }
  }

  return payload
}

const buildConfig = computed(() => {
  const config = {
    log: {
      level: model.value.log.level,
      ...(model.value.log.timestamp ? { timestamp: true } : {}),
      ...(model.value.log.disabled ? { disabled: true } : {}),
    },
    dns: {
      strategy: model.value.dns.strategy,
      final: model.value.dns.final,
      servers: model.value.dns.servers
        .filter((server) => server.address)
        .map((server) => ({
          ...(server.tag ? { tag: server.tag } : {}),
          address: server.address,
          ...(server.detour ? { detour: server.detour } : {}),
          ...(server.address_resolver ? { address_resolver: server.address_resolver } : {}),
          ...(server.strategy ? { strategy: server.strategy } : {}),
        })),
      rules: model.value.dns.rules
        .filter((rule) => rule.server || rule.outbound)
        .map((rule) => ({
          ...(rule.server ? { server: rule.server } : {}),
          ...(rule.outbound ? { outbound: rule.outbound } : {}),
          ...(splitCsv(rule.domain_suffix).length ? { domain_suffix: splitCsv(rule.domain_suffix) } : {}),
          ...(splitCsv(rule.domain_keyword).length ? { domain_keyword: splitCsv(rule.domain_keyword) } : {}),
          ...(splitCsv(rule.geosite).length ? { geosite: splitCsv(rule.geosite) } : {}),
          ...(splitCsv(rule.geoip).length ? { geoip: splitCsv(rule.geoip) } : {}),
          ...(rule.clash_mode ? { clash_mode: rule.clash_mode } : {}),
        })),
    },
    inbounds: model.value.inbounds
      .filter((item) => item.tag)
      .map((item) => ({
        type: item.type,
        tag: item.tag,
        listen: item.listen,
        listen_port: Number(item.listen_port || 1080),
        ...(item.sniff ? { sniff: true } : {}),
        ...(item.sniff_override_destination ? { sniff_override_destination: true } : {}),
        ...(parseJsonSafe(item.users_json, []).length ? { users: parseJsonSafe(item.users_json, []) } : {}),
      })),
    outbounds: model.value.outbounds.filter((item) => item.tag).map(buildOutboundPayload),
    route: {
      ...(model.value.route.auto_detect_interface ? { auto_detect_interface: true } : {}),
      final: model.value.route.final,
      rules: model.value.route.rules
        .filter((rule) => rule.outbound)
        .map((rule) => ({
          outbound: rule.outbound,
          ...(splitCsv(rule.protocol).length ? { protocol: splitCsv(rule.protocol) } : {}),
          ...(splitCsv(rule.domain_suffix).length ? { domain_suffix: splitCsv(rule.domain_suffix) } : {}),
          ...(splitCsv(rule.domain_keyword).length ? { domain_keyword: splitCsv(rule.domain_keyword) } : {}),
          ...(splitCsv(rule.geosite).length ? { geosite: splitCsv(rule.geosite) } : {}),
          ...(splitCsv(rule.geoip).length ? { geoip: splitCsv(rule.geoip) } : {}),
          ...(splitCsv(rule.ip_cidr).length ? { ip_cidr: splitCsv(rule.ip_cidr) } : {}),
          ...(splitCsv(rule.port).length ? { port: splitCsv(rule.port) } : {}),
          ...(splitCsv(rule.network).length ? { network: splitCsv(rule.network) } : {}),
          ...(splitCsv(rule.package_name).length ? { package_name: splitCsv(rule.package_name) } : {}),
          ...(splitCsv(rule.process_name).length ? { process_name: splitCsv(rule.process_name) } : {}),
          ...(rule.clash_mode ? { clash_mode: rule.clash_mode } : {}),
        })),
      rule_set: model.value.route.rule_set
        .filter((item) => item.tag)
        .map((item) => ({
          tag: item.tag,
          type: item.type,
          format: item.format,
          ...(item.url ? { url: item.url } : {}),
          ...(item.path ? { path: item.path } : {}),
          ...(item.download_detour ? { download_detour: item.download_detour } : {}),
          ...(item.update_interval ? { update_interval: item.update_interval } : {}),
        })),
    },
    ...(model.value.ntp.enabled
      ? {
          ntp: {
            enabled: true,
            server: model.value.ntp.server,
            server_port: Number(model.value.ntp.server_port || 123),
          },
        }
      : {}),
    experimental: {
      cache_file: {
        enabled: model.value.experimental.cache_file.enabled,
        ...(model.value.experimental.cache_file.path ? { path: model.value.experimental.cache_file.path } : {}),
      },
      clash_api: {
        external_controller: model.value.experimental.clash_api.external_controller,
        ...(model.value.experimental.clash_api.secret ? { secret: model.value.experimental.clash_api.secret } : {}),
        ...(model.value.experimental.clash_api.default_mode
          ? { default_mode: model.value.experimental.clash_api.default_mode }
          : {}),
        ...(model.value.experimental.clash_api.external_ui ? { external_ui: model.value.experimental.clash_api.external_ui } : {}),
      },
    },
  }

  return Object.assign(config, parseJsonSafe(model.value.extra_json, {}))
})

const configJson = computed(() => JSON.stringify(buildConfig.value, null, 2))

const resetAll = () => {
  model.value = createDefaultModel()
  importText.value = ''
  ElMessage.success('已重置为完整模板')
}

const addItem = (path) => {
  const map = {
    dnsServers: () => model.value.dns.servers.push(createDnsServer()),
    dnsRules: () => model.value.dns.rules.push(createDnsRule()),
    inbounds: () => model.value.inbounds.push(createInbound()),
    outbounds: () => model.value.outbounds.push(createOutbound()),
    routeRules: () => model.value.route.rules.push(createRouteRule()),
    ruleSet: () => model.value.route.rule_set.push(createRuleSet()),
  }

  map[path]?.()
}

const removeAt = (list, index) => {
  list.splice(index, 1)
}

const copyConfig = async () => {
  try {
    await navigator.clipboard.writeText(configJson.value)
    ElMessage.success('配置已复制')
  } catch {
    ElMessage.error('复制失败，请手动复制')
  }
}

const downloadConfig = () => {
  const blob = new Blob([configJson.value], { type: 'application/json;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'sing-box-config.json'
  a.click()
  URL.revokeObjectURL(url)
}

const importConfig = () => {
  if (!importText.value.trim()) {
    ElMessage.warning('请先粘贴配置 JSON')
    return
  }

  try {
    const parsed = JSON.parse(importText.value)

    model.value = {
      log: {
        level: parsed?.log?.level ?? 'info',
        timestamp: parsed?.log?.timestamp !== false,
        disabled: Boolean(parsed?.log?.disabled),
      },
      dns: {
        strategy: parsed?.dns?.strategy ?? 'ipv4_only',
        final: parsed?.dns?.final ?? '',
        servers: (parsed?.dns?.servers ?? []).map((item) => ({
          tag: item.tag ?? '',
          address: item.address ?? '',
          detour: item.detour ?? '',
          address_resolver: item.address_resolver ?? '',
          strategy: item.strategy ?? 'ipv4_only',
        })),
        rules: (parsed?.dns?.rules ?? []).map((item) => ({
          outbound: item.outbound ?? '',
          server: item.server ?? '',
          domain_suffix: toCsv(item.domain_suffix),
          domain_keyword: toCsv(item.domain_keyword),
          geosite: toCsv(item.geosite),
          geoip: toCsv(item.geoip),
          clash_mode: item.clash_mode ?? '',
        })),
      },
      inbounds: (parsed?.inbounds ?? []).map((item) => ({
        type: item.type ?? 'mixed',
        tag: item.tag ?? '',
        listen: item.listen ?? '0.0.0.0',
        listen_port: item.listen_port ?? 1080,
        sniff: item.sniff !== false,
        sniff_override_destination: item.sniff_override_destination !== false,
        users_json: JSON.stringify(item.users ?? [], null, 2),
      })),
      outbounds: (parsed?.outbounds ?? []).map((item) => ({
        type: item.type ?? 'direct',
        tag: item.tag ?? '',
        server: item.server ?? '',
        server_port: item.server_port ?? 443,
        uuid: item.uuid ?? '',
        password: item.password ?? '',
        method: item.method ?? '2022-blake3-aes-128-gcm',
        tls: Boolean(item?.tls?.enabled),
        multiplex: Boolean(item?.multiplex?.enabled),
        outbounds: toCsv(item.outbounds),
        url: item.url ?? 'https://www.gstatic.com/generate_204',
        interval: item.interval ?? '3m',
      })),
      route: {
        auto_detect_interface: parsed?.route?.auto_detect_interface !== false,
        final: parsed?.route?.final ?? '',
        rules: (parsed?.route?.rules ?? []).map((item) => ({
          outbound: item.outbound ?? '',
          protocol: toCsv(item.protocol),
          domain_suffix: toCsv(item.domain_suffix),
          domain_keyword: toCsv(item.domain_keyword),
          geosite: toCsv(item.geosite),
          geoip: toCsv(item.geoip),
          ip_cidr: toCsv(item.ip_cidr),
          port: toCsv(item.port),
          network: toCsv(item.network),
          package_name: toCsv(item.package_name),
          process_name: toCsv(item.process_name),
          clash_mode: item.clash_mode ?? '',
        })),
        rule_set: (parsed?.route?.rule_set ?? []).map((item) => ({
          tag: item.tag ?? '',
          type: item.type ?? 'remote',
          format: item.format ?? 'binary',
          url: item.url ?? '',
          path: item.path ?? '',
          download_detour: item.download_detour ?? '',
          update_interval: item.update_interval ?? '1d',
        })),
      },
      experimental: {
        cache_file: {
          enabled: parsed?.experimental?.cache_file?.enabled !== false,
          path: parsed?.experimental?.cache_file?.path ?? 'cache.db',
        },
        clash_api: {
          external_controller: parsed?.experimental?.clash_api?.external_controller ?? '127.0.0.1:9090',
          secret: parsed?.experimental?.clash_api?.secret ?? '',
          default_mode: parsed?.experimental?.clash_api?.default_mode ?? 'Rule',
          external_ui: parsed?.experimental?.clash_api?.external_ui ?? '',
        },
      },
      ntp: {
        enabled: Boolean(parsed?.ntp?.enabled),
        server: parsed?.ntp?.server ?? 'time.apple.com',
        server_port: parsed?.ntp?.server_port ?? 123,
      },
      extra_json: '{}',
    }

    if (!model.value.dns.servers.length) model.value.dns.servers = [createDnsServer()]
    if (!model.value.dns.rules.length) model.value.dns.rules = [createDnsRule()]
    if (!model.value.inbounds.length) model.value.inbounds = [createInbound()]
    if (!model.value.outbounds.length) model.value.outbounds = [createOutbound()]
    if (!model.value.route.rules.length) model.value.route.rules = [createRouteRule()]
    if (!model.value.route.rule_set.length) model.value.route.rule_set = [createRuleSet()]

    ElMessage.success('配置导入成功')
  } catch {
    ElMessage.error('JSON 解析失败，请检查内容')
  }
}
</script>

<template>
  <div class="page">
    <el-card shadow="never" class="hero">
      <h1>sing-box 完整配置可视化工具</h1>
      <p>中文表单 + 分区标签页，支持完整配置编辑、导入、导出。</p>
      <div class="hero-actions">
        <el-button type="primary" @click="copyConfig">复制 JSON</el-button>
        <el-button type="success" @click="downloadConfig">下载 JSON</el-button>
        <el-button @click="resetAll">恢复模板</el-button>
      </div>
    </el-card>

    <div class="layout">
      <el-card class="panel" shadow="hover">
        <template #header>
          <div class="panel-title">配置编辑器</div>
        </template>

        <el-tabs v-model="activeTab" class="editor-tabs" stretch>
          <el-tab-pane label="基础" name="basic">
            <el-form label-position="top">
              <el-row :gutter="12">
                <el-col :span="12">
                  <el-form-item label="日志级别">
                    <el-select v-model="model.log.level">
                      <el-option label="trace" value="trace" />
                      <el-option label="debug" value="debug" />
                      <el-option label="info" value="info" />
                      <el-option label="warn" value="warn" />
                      <el-option label="error" value="error" />
                      <el-option label="fatal" value="fatal" />
                      <el-option label="panic" value="panic" />
                    </el-select>
                  </el-form-item>
                </el-col>
                <el-col :span="12" class="switch-col">
                  <div class="switch-item"><el-switch v-model="model.log.timestamp" /> 日志时间戳</div>
                  <div class="switch-item"><el-switch v-model="model.log.disabled" /> 禁用日志</div>
                </el-col>
              </el-row>

              <el-divider content-position="left">NTP（可选）</el-divider>
              <el-space>
                <el-switch v-model="model.ntp.enabled" /> 启用 NTP
              </el-space>
              <el-row :gutter="12">
                <el-col :span="16"><el-form-item label="NTP 服务器"><el-input v-model="model.ntp.server" /></el-form-item></el-col>
                <el-col :span="8"><el-form-item label="NTP 端口"><el-input-number v-model="model.ntp.server_port" :min="1" :max="65535" /></el-form-item></el-col>
              </el-row>
            </el-form>
          </el-tab-pane>

          <el-tab-pane label="DNS" name="dns">
            <el-form label-position="top">
              <el-row :gutter="12">
                <el-col :span="12">
                  <el-form-item label="DNS 策略">
                    <el-select v-model="model.dns.strategy">
                      <el-option label="ipv4_only" value="ipv4_only" />
                      <el-option label="ipv6_only" value="ipv6_only" />
                      <el-option label="prefer_ipv4" value="prefer_ipv4" />
                      <el-option label="prefer_ipv6" value="prefer_ipv6" />
                    </el-select>
                  </el-form-item>
                </el-col>
                <el-col :span="12">
                  <el-form-item label="最终 DNS 标签">
                    <el-select v-model="model.dns.final" filterable allow-create default-first-option>
                      <el-option v-for="tag in dnsTags" :key="tag" :label="tag" :value="tag" />
                    </el-select>
                  </el-form-item>
                </el-col>
              </el-row>

              <el-divider content-position="left">DNS 服务器</el-divider>
              <div v-for="(server, index) in model.dns.servers" :key="`dns-server-${index}`" class="block">
                <div class="block-title">服务器 #{{ index + 1 }}</div>
                <el-row :gutter="12">
                  <el-col :span="12"><el-form-item label="标签"><el-input v-model="server.tag" /></el-form-item></el-col>
                  <el-col :span="12"><el-form-item label="地址"><el-input v-model="server.address" placeholder="https://1.1.1.1/dns-query" /></el-form-item></el-col>
                </el-row>
                <el-row :gutter="12">
                  <el-col :span="12"><el-form-item label="Detour"><el-input v-model="server.detour" /></el-form-item></el-col>
                  <el-col :span="12"><el-form-item label="Address Resolver"><el-input v-model="server.address_resolver" /></el-form-item></el-col>
                </el-row>
                <el-form-item label="策略">
                  <el-select v-model="server.strategy">
                    <el-option label="ipv4_only" value="ipv4_only" />
                    <el-option label="ipv6_only" value="ipv6_only" />
                    <el-option label="prefer_ipv4" value="prefer_ipv4" />
                    <el-option label="prefer_ipv6" value="prefer_ipv6" />
                  </el-select>
                </el-form-item>
                <el-button text type="danger" :disabled="model.dns.servers.length <= 1" @click="removeAt(model.dns.servers, index)">删除服务器</el-button>
              </div>
              <el-button plain @click="addItem('dnsServers')">+ 添加 DNS 服务器</el-button>

              <el-divider content-position="left">DNS 规则</el-divider>
              <div v-for="(rule, index) in model.dns.rules" :key="`dns-rule-${index}`" class="block">
                <div class="block-title">规则 #{{ index + 1 }}</div>
                <el-row :gutter="12">
                  <el-col :span="12"><el-form-item label="命中后 DNS 服务器"><el-input v-model="rule.server" /></el-form-item></el-col>
                  <el-col :span="12"><el-form-item label="命中后出站"><el-input v-model="rule.outbound" /></el-form-item></el-col>
                </el-row>
                <el-form-item label="domain_suffix（逗号分隔）"><el-input v-model="rule.domain_suffix" /></el-form-item>
                <el-form-item label="domain_keyword（逗号分隔）"><el-input v-model="rule.domain_keyword" /></el-form-item>
                <el-form-item label="geosite（逗号分隔）"><el-input v-model="rule.geosite" /></el-form-item>
                <el-form-item label="geoip（逗号分隔）"><el-input v-model="rule.geoip" /></el-form-item>
                <el-form-item label="clash 模式"><el-input v-model="rule.clash_mode" placeholder="Rule / Global / Direct" /></el-form-item>
                <el-button text type="danger" :disabled="model.dns.rules.length <= 1" @click="removeAt(model.dns.rules, index)">删除规则</el-button>
              </div>
              <el-button plain @click="addItem('dnsRules')">+ 添加 DNS 规则</el-button>
            </el-form>
          </el-tab-pane>

          <el-tab-pane label="入站 Inbounds" name="inbounds">
            <div v-for="(inbound, index) in model.inbounds" :key="`inbound-${index}`" class="block">
              <div class="block-title">入站 #{{ index + 1 }}</div>
              <el-form label-position="top">
                <el-row :gutter="12">
                  <el-col :span="8">
                    <el-form-item label="类型">
                      <el-select v-model="inbound.type">
                        <el-option label="mixed" value="mixed" />
                        <el-option label="socks" value="socks" />
                        <el-option label="http" value="http" />
                        <el-option label="tun" value="tun" />
                        <el-option label="redirect" value="redirect" />
                        <el-option label="tproxy" value="tproxy" />
                      </el-select>
                    </el-form-item>
                  </el-col>
                  <el-col :span="8"><el-form-item label="标签"><el-input v-model="inbound.tag" /></el-form-item></el-col>
                  <el-col :span="8"><el-form-item label="监听地址"><el-input v-model="inbound.listen" /></el-form-item></el-col>
                </el-row>
                <el-form-item label="监听端口"><el-input-number v-model="inbound.listen_port" :min="1" :max="65535" /></el-form-item>
                <el-space>
                  <el-switch v-model="inbound.sniff" /> 启用 sniff
                  <el-switch v-model="inbound.sniff_override_destination" /> 覆盖目标地址
                </el-space>
                <el-form-item label="用户列表（JSON 数组，可留空）">
                  <el-input v-model="inbound.users_json" type="textarea" :rows="4" placeholder='[{"username":"u","password":"p"}]' />
                </el-form-item>
              </el-form>
              <el-button text type="danger" :disabled="model.inbounds.length <= 1" @click="removeAt(model.inbounds, index)">删除入站</el-button>
            </div>
            <el-button plain @click="addItem('inbounds')">+ 添加入站</el-button>
          </el-tab-pane>

          <el-tab-pane label="出站 Outbounds" name="outbounds">
            <div v-for="(outbound, index) in model.outbounds" :key="`outbound-${index}`" class="block">
              <div class="block-title">出站 #{{ index + 1 }}</div>
              <el-form label-position="top">
                <el-row :gutter="12">
                  <el-col :span="10">
                    <el-form-item label="类型">
                      <el-select v-model="outbound.type">
                        <el-option label="selector" value="selector" />
                        <el-option label="urltest" value="urltest" />
                        <el-option label="direct" value="direct" />
                        <el-option label="block" value="block" />
                        <el-option label="dns" value="dns" />
                        <el-option label="vless" value="vless" />
                        <el-option label="vmess" value="vmess" />
                        <el-option label="trojan" value="trojan" />
                        <el-option label="shadowsocks" value="shadowsocks" />
                        <el-option label="hysteria2" value="hysteria2" />
                      </el-select>
                    </el-form-item>
                  </el-col>
                  <el-col :span="14"><el-form-item label="标签"><el-input v-model="outbound.tag" /></el-form-item></el-col>
                </el-row>

                <template v-if="['selector', 'urltest'].includes(outbound.type)">
                  <el-form-item label="包含节点（逗号分隔）"><el-input v-model="outbound.outbounds" placeholder="auto,direct,proxy-a" /></el-form-item>
                </template>
                <template v-if="outbound.type === 'urltest'">
                  <el-row :gutter="12">
                    <el-col :span="16"><el-form-item label="测速 URL"><el-input v-model="outbound.url" /></el-form-item></el-col>
                    <el-col :span="8"><el-form-item label="测速间隔"><el-input v-model="outbound.interval" placeholder="3m" /></el-form-item></el-col>
                  </el-row>
                </template>

                <template v-if="['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria2'].includes(outbound.type)">
                  <el-row :gutter="12">
                    <el-col :span="16"><el-form-item label="服务器地址"><el-input v-model="outbound.server" /></el-form-item></el-col>
                    <el-col :span="8"><el-form-item label="端口"><el-input-number v-model="outbound.server_port" :min="1" :max="65535" /></el-form-item></el-col>
                  </el-row>
                </template>

                <el-form-item v-if="['vless', 'vmess'].includes(outbound.type)" label="UUID"><el-input v-model="outbound.uuid" /></el-form-item>
                <el-form-item v-if="['trojan', 'shadowsocks', 'hysteria2'].includes(outbound.type)" label="密码"><el-input v-model="outbound.password" /></el-form-item>
                <el-form-item v-if="outbound.type === 'shadowsocks'" label="加密方法"><el-input v-model="outbound.method" /></el-form-item>

                <el-space>
                  <el-switch v-model="outbound.tls" /> 开启 TLS
                  <el-switch v-model="outbound.multiplex" /> 开启复用 Multiplex
                </el-space>
              </el-form>
              <el-button text type="danger" :disabled="model.outbounds.length <= 1" @click="removeAt(model.outbounds, index)">删除出站</el-button>
            </div>
            <el-button plain @click="addItem('outbounds')">+ 添加出站</el-button>
          </el-tab-pane>

          <el-tab-pane label="路由 Route" name="route">
            <el-form label-position="top">
              <el-row :gutter="12">
                <el-col :span="12">
                  <el-form-item label="默认出站 final">
                    <el-select v-model="model.route.final" filterable allow-create default-first-option>
                      <el-option v-for="tag in outboundTags" :key="tag" :label="tag" :value="tag" />
                    </el-select>
                  </el-form-item>
                </el-col>
                <el-col :span="12" class="switch-col">
                  <div class="switch-item"><el-switch v-model="model.route.auto_detect_interface" /> 自动识别网卡</div>
                </el-col>
              </el-row>

              <el-divider content-position="left">路由规则 route.rules</el-divider>
              <div v-for="(rule, index) in model.route.rules" :key="`route-rule-${index}`" class="block">
                <div class="block-title">路由规则 #{{ index + 1 }}</div>
                <el-form-item label="命中后出站"><el-input v-model="rule.outbound" /></el-form-item>
                <el-form-item label="协议 protocol（逗号分隔）"><el-input v-model="rule.protocol" /></el-form-item>
                <el-form-item label="domain_suffix（逗号分隔）"><el-input v-model="rule.domain_suffix" /></el-form-item>
                <el-form-item label="domain_keyword（逗号分隔）"><el-input v-model="rule.domain_keyword" /></el-form-item>
                <el-form-item label="geosite（逗号分隔）"><el-input v-model="rule.geosite" /></el-form-item>
                <el-form-item label="geoip（逗号分隔）"><el-input v-model="rule.geoip" /></el-form-item>
                <el-form-item label="ip_cidr（逗号分隔）"><el-input v-model="rule.ip_cidr" /></el-form-item>
                <el-form-item label="端口 port（逗号分隔）"><el-input v-model="rule.port" /></el-form-item>
                <el-form-item label="网络 network（逗号分隔）"><el-input v-model="rule.network" /></el-form-item>
                <el-form-item label="包名 package_name（逗号分隔）"><el-input v-model="rule.package_name" /></el-form-item>
                <el-form-item label="进程 process_name（逗号分隔）"><el-input v-model="rule.process_name" /></el-form-item>
                <el-form-item label="clash_mode"><el-input v-model="rule.clash_mode" /></el-form-item>
                <el-button text type="danger" :disabled="model.route.rules.length <= 1" @click="removeAt(model.route.rules, index)">删除规则</el-button>
              </div>
              <el-button plain @click="addItem('routeRules')">+ 添加路由规则</el-button>

              <el-divider content-position="left">规则集 route.rule_set</el-divider>
              <div v-for="(item, index) in model.route.rule_set" :key="`rule-set-${index}`" class="block">
                <div class="block-title">规则集 #{{ index + 1 }}</div>
                <el-row :gutter="12">
                  <el-col :span="12"><el-form-item label="标签"><el-input v-model="item.tag" /></el-form-item></el-col>
                  <el-col :span="12"><el-form-item label="类型"><el-select v-model="item.type"><el-option label="remote" value="remote" /><el-option label="local" value="local" /></el-select></el-form-item></el-col>
                </el-row>
                <el-row :gutter="12">
                  <el-col :span="12"><el-form-item label="格式"><el-select v-model="item.format"><el-option label="binary" value="binary" /><el-option label="source" value="source" /></el-select></el-form-item></el-col>
                  <el-col :span="12"><el-form-item label="更新间隔"><el-input v-model="item.update_interval" placeholder="1d" /></el-form-item></el-col>
                </el-row>
                <el-form-item label="URL"><el-input v-model="item.url" /></el-form-item>
                <el-form-item label="本地路径"><el-input v-model="item.path" /></el-form-item>
                <el-form-item label="下载出口"><el-input v-model="item.download_detour" /></el-form-item>
                <el-button text type="danger" :disabled="model.route.rule_set.length <= 1" @click="removeAt(model.route.rule_set, index)">删除规则集</el-button>
              </div>
              <el-button plain @click="addItem('ruleSet')">+ 添加规则集</el-button>
            </el-form>
          </el-tab-pane>

          <el-tab-pane label="实验功能" name="experimental">
            <el-form label-position="top">
              <el-divider content-position="left">缓存文件 experimental.cache_file</el-divider>
              <el-space><el-switch v-model="model.experimental.cache_file.enabled" /> 启用缓存文件</el-space>
              <el-form-item label="缓存文件路径"><el-input v-model="model.experimental.cache_file.path" placeholder="cache.db" /></el-form-item>

              <el-divider content-position="left">Clash API experimental.clash_api</el-divider>
              <el-form-item label="控制器地址"><el-input v-model="model.experimental.clash_api.external_controller" /></el-form-item>
              <el-form-item label="访问密钥"><el-input v-model="model.experimental.clash_api.secret" /></el-form-item>
              <el-form-item label="默认模式"><el-input v-model="model.experimental.clash_api.default_mode" /></el-form-item>
              <el-form-item label="外部 UI 路径"><el-input v-model="model.experimental.clash_api.external_ui" /></el-form-item>

              <el-divider content-position="left">高级补充 extra_json（合并到根配置）</el-divider>
              <el-form-item>
                <el-input v-model="model.extra_json" type="textarea" :rows="8" placeholder='{"certificate":[...],"custom":{}}' />
              </el-form-item>
            </el-form>
          </el-tab-pane>
        </el-tabs>
      </el-card>

      <el-card class="panel" shadow="hover">
        <template #header><div class="panel-title">JSON 预览 / 导入</div></template>
        <el-form label-position="top">
          <el-form-item label="当前生成配置（只读）">
            <el-input :model-value="configJson" type="textarea" :rows="28" readonly />
          </el-form-item>
          <el-form-item label="粘贴 sing-box JSON 并导入">
            <el-input v-model="importText" type="textarea" :rows="12" placeholder="粘贴完整 JSON 后点击下方按钮" />
          </el-form-item>
          <el-button type="primary" @click="importConfig">导入并覆盖当前表单</el-button>
        </el-form>
      </el-card>
    </div>
  </div>
</template>

<style scoped>
.page {
  max-width: 1520px;
  margin: 0 auto;
  padding: 20px;
}

.hero {
  margin-bottom: 16px;
}

.hero h1 {
  margin: 0;
  font-size: 24px;
}

.hero p {
  margin: 8px 0 0;
  color: #6b7280;
}

.hero-actions {
  margin-top: 14px;
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}

.layout {
  display: grid;
  grid-template-columns: 1.25fr 1fr;
  gap: 16px;
}

.panel {
  min-height: 700px;
}

.panel-title {
  font-weight: 600;
}

.editor-tabs :deep(.el-tabs__content) {
  max-height: 68vh;
  overflow: auto;
  padding-right: 4px;
}

.block {
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  padding: 12px;
  background: #fafafa;
  margin-bottom: 10px;
}

.block-title {
  margin-bottom: 8px;
  font-weight: 600;
  color: #111827;
}

.switch-col {
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 10px;
}

.switch-item {
  color: #4b5563;
}

@media (max-width: 1100px) {
  .layout {
    grid-template-columns: 1fr;
  }

  .editor-tabs :deep(.el-tabs__content) {
    max-height: none;
  }
}
</style>
