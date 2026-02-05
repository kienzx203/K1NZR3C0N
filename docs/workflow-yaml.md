# Tài liệu cấu trúc YAML workflow

Tài liệu này mô tả cấu trúc file YAML dùng để định nghĩa workflow cho dự án `k1nzr3c0n`.

## Tổng quan
- File YAML gồm các phần chính: `name`, `vars`, và `steps`.
- Mỗi `step` là một bước chạy lệnh shell theo thứ tự phụ thuộc.
- Hỗ trợ template placeholder dạng `{key}` để tham chiếu biến.

## Cấu trúc tổng quát
```yaml
name: <tên-workflow>
vars:
  <key>: <value>
steps:
  - id: <id-bước>
    name: <mô tả ngắn>
    run: '<lệnh-shell>'
    depends_on: [<id-bước-khác>]
    outputs:
      <key>: '<path-template>'
    requires:
      - path: '<path-template>'
        min_bytes: <số-byte-tối-thiểu>
    skip_if_exists: <true|false>
    fanout_concurrency: <số-luồng-song-song>
    fanout_timeout_default: <timeout-mặc-định>
    fanout:
      - id: <id-con>
        run: '<lệnh-shell>'
        outputs:
          <key>: '<path-template>'
        requires:
          - path: '<path-template>'
            min_bytes: <số-byte-tối-thiểu>
        skip_if_exists: <true|false>
    retries: <số-lần-thử-lại>
    timeout: <giây>
    cwd: <thư-mục-làm-việc>
    env:
      <ENV_KEY>: '<value-template>'
    run_on_failed_deps: <true|false>
  - id: <id-gọi-workflow>
    workflow: <đường-dẫn-workflow-khác>
    namespace: <tiền-tố-namespace>
    depends_on: [<id-bước-khác>]
```

## Các trường chi tiết

### `name` (string)
Tên workflow. Dùng để nhận diện, không ảnh hưởng logic.

### `vars` (mapping, optional)
Biến dùng chung trong workflow. Có thể được override qua CLI `--vars key=value`.

Ví dụ:
```yaml
vars:
  httpx_bin: /home/user/go/bin/httpx
  rate: 100
```

### `steps` (list, bắt buộc)
Danh sách các step. Mỗi step là một mapping.

#### `id` (string, bắt buộc)
ID duy nhất của step. Dùng để tham chiếu trong `depends_on` và `steps.<id>.*`.

#### `name` (string, optional)
Mô tả ngắn cho step.

#### `run` (string, bắt buộc)
Lệnh shell sẽ thực thi. Hỗ trợ template placeholder.

Ví dụ:
```yaml
run: 'subfinder -d {target} -silent -o {workspace}/subs.txt'
```

#### `depends_on` (list|string, optional)
Danh sách các step ID phải hoàn thành trước khi step này chạy.

Ví dụ:
```yaml
depends_on: ['subfinder']
```

#### `outputs` (mapping, optional)
Khai báo các output để step khác tham chiếu.

Ví dụ:
```yaml
outputs:
  subs_file: '{workspace}/subs.txt'
```
Khi đó có thể dùng `{steps.subfinder.subs_file}`.

#### `requires` (list, optional)
Kiểm tra điều kiện sau khi step chạy xong. Nếu fail thì step bị đánh fail.

Ví dụ:
```yaml
requires:
  - path: '{workspace}/subs.txt'
    min_bytes: 1
```

#### `retries` (int, optional)
Số lần retry nếu step fail. Mặc định `0`.

#### `skip_if_exists` (bool, optional)
Nếu `true`, step sẽ bị skip khi output đã tồn tại và hợp lệ (dựa vào `requires` hoặc `outputs`).
Kết hợp tốt với `--resume` khi bạn muốn tiếp tục chạy dở.

#### `fanout` (list, optional)
Cho phép chạy nhiều tool **song song** trong cùng một step. Mỗi item trong `fanout` có cấu trúc giống một step con (`id`, `run`, `outputs`, `requires`, `skip_if_exists`, ...).

Lưu ý:
- Khi `fanout` tồn tại, **không dùng** `run` ở step cha.
- Output của fanout có thể tham chiếu theo dạng `{steps.<id_step>.<id_con>.<output_key>}`.

#### `fanout_concurrency` (int, optional)
Giới hạn số lượng tool chạy song song trong `fanout`. Mặc định min(4, số tool).

#### `fanout_timeout_default` (int|float|string, optional)
Timeout mặc định cho mọi tool trong `fanout` nếu tool con không khai báo `timeout`.
Hỗ trợ định dạng `30`, `45s`, `2m`, `1h`.

#### `workflow` (string, optional)
Cho phép gọi một workflow YAML khác và **nhúng** các step vào workflow hiện tại.
Khi dùng `workflow`, step cha **không** được khai báo `run` hoặc `fanout`.
`vars` của workflow con sẽ được merge như **giá trị mặc định** (nếu parent chưa có key đó).

#### `namespace` (string, optional)
Tiền tố namespace cho các step của workflow con. Mặc định là `id` của step gọi.
Tất cả step của workflow con sẽ được đổi id thành `<namespace>.<id_con>`.

#### `depends_on` với workflow include
Nếu step gọi workflow có `depends_on`, các dependency đó sẽ được áp vào **mọi step con**.

#### `timeout` (float|int, optional)
Timeout cho lệnh (giây). Mặc định không giới hạn.

#### `cwd` (string, optional)
Thư mục làm việc cho step. Nếu là path tương đối thì tính từ `workspace`.

#### `env` (mapping, optional)
Thiết lập biến môi trường cho step.

Ví dụ:
```yaml
env:
  API_KEY: '{vars.api_key}'
```

#### `run_on_failed_deps` (bool, optional)
Nếu `true`, step vẫn chạy dù dependency fail. Mặc định `false`.

## Placeholder templates
Các placeholder có thể dùng trong `run`, `outputs`, `requires`, `cwd`, `env`:

- `{target}`: target do CLI truyền vào `-t`
- `{workspace}`: thư mục workspace hiện tại
- `{timestamp}`: thời gian chạy dạng `YYYYMMDD-HHMMSS`
- `{vars.<key>}`: biến từ `vars`
- `{steps.<id>.<output_key>}`: output đã khai báo của step trước
- `{steps.<id_step>.<id_con>.<output_key>}`: output của fanout
- Với include workflow, tham chiếu sẽ là `{steps.<namespace>.<id_con>.<output_key>}`

## Timeout
`timeout` hỗ trợ số giây hoặc chuỗi có hậu tố:
- `30` hoặc `30s` = 30 giây
- `2m` = 120 giây
- `1h` = 3600 giây

## Include workflow
Ví dụ gọi workflow con:
```yaml
- id: recon_child
  workflow: workflows/recon-basic.yaml
  namespace: child
  depends_on: ['subfinder']
```

Sau include, bạn có thể tham chiếu output của workflow con như:
```
{steps.child.httpx.alive_file}
```

## Ví dụ workflow cơ bản
```yaml
name: recon-basic
vars:
  httpx_bin: /home/user/go/bin/httpx
steps:
  - id: subfinder
    name: subdomain enumeration
    run: 'subfinder -d {target} -silent -o {workspace}/subs.txt'
    outputs:
      subs_file: '{workspace}/subs.txt'
    requires:
      - path: '{workspace}/subs.txt'
        min_bytes: 1
    skip_if_exists: true
  - id: httpx
    name: http probe
    depends_on: ['subfinder']
    run: '{vars.httpx_bin} -l {steps.subfinder.subs_file} -silent -o {workspace}/alive.txt'
    outputs:
      alive_file: '{workspace}/alive.txt'
    requires:
      - path: '{workspace}/alive.txt'
        min_bytes: 1
    skip_if_exists: true
  - id: nuclei
    name: vuln scan
    depends_on: ['httpx']
    run: 'nuclei -l {steps.httpx.alive_file} -o {workspace}/nuclei.txt'
```

## Gợi ý vận hành
- Dùng `--print-plan` để xem lệnh đã render.
- Nếu muốn không fail khi output rỗng, đặt `min_bytes: 0` hoặc bỏ `requires`.
- Dùng `--out` và `--resume` để tiếp tục một lần scan trước đó.
