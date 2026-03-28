<script setup>
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'

const form = ref({
  logLevel: 'info',
  dnsServer: 'https://1.1.1.1/dns-query',
  inTag: 'mixed-in',
  inListen: '0.0.0.0',
  inPort: 2080,
  outTag: 'proxy-out',
  outType: 'direct',
  server: '',
  serverPort: 443,
  uuid: '',
})

const importText = ref('')

const baseConfig = computed(() => ({
  log: {
    level: form.value.logLevel,
  },
  dns: {
    servers: [
      {
        tag: 'dns-remote',
        address: form.value.dnsServer,
      },
    ],
  },
  inbounds: [
    {
      type: 'mixed',
      tag: form.value.inTag,
      listen: form.value.inListen,
      listen_port: Number(form.value.inPort),
      users: [],
    },
  ],
  outbounds: [
    {
      type: form.value.outType,
      tag: form.value.outTag,
      ...(form.value.outType === 'vless'
        ? {
            server: form.value.server,
            server_port: Number(form.value.serverPort),
            uuid: form.value.uuid,
            tls: {
              enabled: true,
            },
          }
        : {}),
    },
  ],
  route: {
    final: form.value.outTag,
  },
}))

const configJson = computed(() => JSON.stringify(baseConfig.value, null, 2))

const resetForm = () => {
  form.value = {
    logLevel: 'info',
    dnsServer: 'https://1.1.1.1/dns-query',
    inTag: 'mixed-in',
    inListen: '0.0.0.0',
    inPort: 2080,
    outTag: 'proxy-out',
    outType: 'direct',
    server: '',
    serverPort: 443,
    uuid: '',
  }
  importText.value = ''
}

const copyConfig = async () => {
  try {
    await navigator.clipboard.writeText(configJson.value)
    ElMessage.success('配置已复制到剪贴板')
  } catch {
    ElMessage.error('复制失败，请手动复制')
  }
}

const importConfig = () => {
  if (!importText.value.trim()) {
    ElMessage.warning('请先粘贴 JSON 配置')
    return
  }

  try {
    const parsed = JSON.parse(importText.value)

    form.value.logLevel = parsed?.log?.level ?? 'info'
    form.value.dnsServer = parsed?.dns?.servers?.[0]?.address ?? 'https://1.1.1.1/dns-query'

    const inbound = parsed?.inbounds?.[0] ?? {}
    form.value.inTag = inbound.tag ?? 'mixed-in'
    form.value.inListen = inbound.listen ?? '0.0.0.0'
    form.value.inPort = inbound.listen_port ?? 2080

    const outbound = parsed?.outbounds?.[0] ?? {}
    form.value.outTag = outbound.tag ?? 'proxy-out'
    form.value.outType = outbound.type ?? 'direct'
    form.value.server = outbound.server ?? ''
    form.value.serverPort = outbound.server_port ?? 443
    form.value.uuid = outbound.uuid ?? ''

    ElMessage.success('导入成功，已同步到可视化表单')
  } catch {
    ElMessage.error('JSON 解析失败，请检查格式')
  }
}
</script>

<template>
  <div class="page">
    <el-card shadow="never" class="header-card">
      <h1>sing-box 配置可视化工具</h1>
      <p>基于 Vue 3 + Element Plus，只做最常用单节点配置快速生成与编辑。</p>
    </el-card>

    <div class="layout">
      <el-card shadow="hover" class="panel">
        <template #header>
          <span>可视化编辑</span>
        </template>

        <el-form label-position="top" :model="form">
          <el-divider content-position="left">基础</el-divider>
          <el-form-item label="日志等级">
            <el-select v-model="form.logLevel">
              <el-option label="trace" value="trace" />
              <el-option label="debug" value="debug" />
              <el-option label="info" value="info" />
              <el-option label="warn" value="warn" />
              <el-option label="error" value="error" />
            </el-select>
          </el-form-item>

          <el-form-item label="DNS 服务器地址">
            <el-input v-model="form.dnsServer" placeholder="https://1.1.1.1/dns-query" />
          </el-form-item>

          <el-divider content-position="left">Inbound</el-divider>
          <el-form-item label="Inbound Tag">
            <el-input v-model="form.inTag" />
          </el-form-item>
          <el-form-item label="监听地址">
            <el-input v-model="form.inListen" />
          </el-form-item>
          <el-form-item label="监听端口">
            <el-input-number v-model="form.inPort" :min="1" :max="65535" />
          </el-form-item>

          <el-divider content-position="left">Outbound</el-divider>
          <el-form-item label="Outbound Tag">
            <el-input v-model="form.outTag" />
          </el-form-item>
          <el-form-item label="类型">
            <el-select v-model="form.outType">
              <el-option label="direct" value="direct" />
              <el-option label="block" value="block" />
              <el-option label="dns" value="dns" />
              <el-option label="vless" value="vless" />
            </el-select>
          </el-form-item>

          <template v-if="form.outType === 'vless'">
            <el-form-item label="服务器地址">
              <el-input v-model="form.server" placeholder="example.com" />
            </el-form-item>
            <el-form-item label="服务器端口">
              <el-input-number v-model="form.serverPort" :min="1" :max="65535" />
            </el-form-item>
            <el-form-item label="UUID">
              <el-input v-model="form.uuid" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" />
            </el-form-item>
          </template>

          <el-space>
            <el-button type="primary" @click="copyConfig">复制配置</el-button>
            <el-button @click="resetForm">重置</el-button>
          </el-space>
        </el-form>
      </el-card>

      <el-card shadow="hover" class="panel">
        <template #header>
          <span>JSON 预览 / 导入</span>
        </template>

        <el-form label-position="top">
          <el-form-item label="自动生成配置（只读）">
            <el-input type="textarea" :rows="16" :model-value="configJson" readonly />
          </el-form-item>

          <el-form-item label="粘贴配置 JSON 并导入">
            <el-input v-model="importText" type="textarea" :rows="10" placeholder="在这里粘贴现有 sing-box 配置" />
          </el-form-item>
          <el-button type="success" @click="importConfig">导入到表单</el-button>
        </el-form>
      </el-card>
    </div>
  </div>
</template>

<style scoped>
.page {
  padding: 20px;
  max-width: 1280px;
  margin: 0 auto;
}

.header-card {
  margin-bottom: 16px;
}

.header-card h1 {
  margin: 0;
  font-size: 24px;
}

.header-card p {
  margin: 8px 0 0;
  color: #6b7280;
}

.layout {
  display: grid;
  grid-template-columns: repeat(2, minmax(300px, 1fr));
  gap: 16px;
}

.panel {
  min-height: 600px;
}

@media (max-width: 980px) {
  .layout {
    grid-template-columns: 1fr;
  }
}
</style>
