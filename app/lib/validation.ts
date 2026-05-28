import { z } from "zod"

export const authSchema = z.object({
  username: z.string()
    .min(1, "用户名不能为空")
    .max(20, "用户名不能超过20个字符")
    .regex(/^[a-zA-Z0-9_-]+$/, "用户名只能包含字母、数字、下划线和横杠")
    .refine(val => !val.includes('@'), "用户名不能是邮箱格式"),
  password: z.string()
    .min(8, "密码长度必须大于等于8位"),
  turnstileToken: z.string().optional()
})

export type AuthSchema = z.infer<typeof authSchema>

const BLOCKED_HOSTS = /^(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+|0\.0\.0\.0|\[::1?\])$/i

export function isPublicUrl(urlString: string): boolean {
  try {
    const url = new URL(urlString)
    if (url.protocol !== "https:" && url.protocol !== "http:") return false
    if (BLOCKED_HOSTS.test(url.hostname)) return false
    return true
  } catch {
    return false
  }
}
