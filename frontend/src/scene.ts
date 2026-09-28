import * as THREE from 'three'
import { RoundedBoxGeometry } from 'three/addons/geometries/RoundedBoxGeometry.js'
import { RoomEnvironment } from 'three/addons/environments/RoomEnvironment.js'
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js'
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js'
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js'
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js'

/** Original procedural artwork. No downloaded models, videos, textures or HDRIs. */
export function mountScene(container: HTMLElement, mode: 'pipeline' | 'agents') {
  let disposed = false
  let visible = false
  let running = false
  let motionPaused = false
  let contextAvailable = true
  let frame = 0
  let time = 0
  let previous = 0
  const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)')
  const scene = new THREE.Scene()
  scene.background = new THREE.Color('#080909')
  const camera = new THREE.OrthographicCamera(-4, 4, 4, -4, 0.1, 100)
  camera.position.set(mode === 'pipeline' ? 6.7 : 3.4, mode === 'pipeline' ? 5 : 1.8, 10)
  camera.lookAt(0, mode === 'pipeline' ? 0.2 : 0.1, 0)
  const renderer = new THREE.WebGLRenderer({
    antialias: true,
    alpha: false,
    powerPreference: 'low-power',
  })
  renderer.setPixelRatio(Math.min(devicePixelRatio, 1.5))
  renderer.toneMapping = THREE.ACESFilmicToneMapping
  renderer.toneMappingExposure = 1
  renderer.outputColorSpace = THREE.SRGBColorSpace
  renderer.domElement.setAttribute('aria-hidden', 'true')
  renderer.domElement.className = 'scene-canvas'
  container.append(renderer.domElement)
  const environment = new RoomEnvironment()
  const pmrem = new THREE.PMREMGenerator(renderer)
  const environmentTarget = pmrem.fromScene(environment, 0.04)
  scene.environment = environmentTarget.texture
  environment.dispose()
  pmrem.dispose()
  const composer = new EffectComposer(renderer)
  composer.addPass(new RenderPass(scene, camera))
  const bloom = new UnrealBloomPass(new THREE.Vector2(600, 600), 0.24, 0.28, 1.8)
  composer.addPass(bloom)
  composer.addPass(new OutputPass())

  const metal = new THREE.MeshPhysicalMaterial({
    color: '#929797',
    metalness: 0.86,
    roughness: 0.27,
    clearcoat: 1,
    clearcoatRoughness: 0.22,
    envMapIntensity: 1.05,
  })
  const charcoal = new THREE.MeshStandardMaterial({
    color: '#202222',
    metalness: 0.8,
    roughness: 0.32,
  })
  const glass = new THREE.MeshPhysicalMaterial({
    color: '#090a0a',
    metalness: 0.5,
    roughness: 0.13,
    clearcoat: 1,
  })
  const sensorRed = new THREE.MeshStandardMaterial({
    color: '#ffaaaa',
    emissive: '#c9323c',
    emissiveIntensity: 1.2,
    roughness: 0.2,
    metalness: 0.2,
  })
  const crimson = new THREE.MeshStandardMaterial({
    color: '#bb3038',
    emissive: '#9b1e26',
    emissiveIntensity: 0.9,
  })
  const pearl = new THREE.MeshStandardMaterial({
    color: '#f4f4f4',
    emissive: '#cccccc',
    emissiveIntensity: 0.3,
  })
  scene.add(new THREE.HemisphereLight('#eeeeee', '#261719', 1.2))
  const key = new THREE.DirectionalLight('#fff5f5', 3)
  key.position.set(-3, 6, 5)
  scene.add(key)
  const rim = new THREE.DirectionalLight('#cf9292', 3)
  rim.position.set(4, 3, -3)
  scene.add(rim)
  const portalLight = new THREE.PointLight('#c9323c', 6, 7, 2)
  portalLight.position.set(0, 0.1, 0)
  scene.add(portalLight)

  function mesh(
    geometry: THREE.BufferGeometry,
    material: THREE.Material,
    parent: THREE.Object3D,
    position = new THREE.Vector3(),
  ) {
    const result = new THREE.Mesh(geometry, material)
    result.position.copy(position)
    parent.add(result)
    return result
  }
  function rounded(w: number, h: number, d: number, radius = 0.16) {
    return new RoundedBoxGeometry(w, h, d, 4, radius)
  }
  function tube(
    points: THREE.Vector3[],
    radius: number,
    material: THREE.Material,
    parent: THREE.Object3D,
    closed = false,
  ) {
    return mesh(
      new THREE.TubeGeometry(new THREE.CatmullRomCurve3(points, closed), 48, radius, 8, closed),
      material,
      parent,
    )
  }
  function robot() {
    const group = new THREE.Group()
    const head = new THREE.Group()
    group.add(head)
    mesh(rounded(1.72, 1.35, 1.16, 0.26), metal, head)
    mesh(rounded(1.43, 1.09, 0.2, 0.22), charcoal, head, new THREE.Vector3(0, 0.03, 0.55))
    mesh(rounded(1.29, 0.95, 0.12, 0.19), glass, head, new THREE.Vector3(0, 0.03, 0.65))
    const eyes = [-0.29, 0.29].map((x) => {
      const eye = mesh(
        rounded(0.34, 0.22, 0.085, 0.09),
        sensorRed,
        head,
        new THREE.Vector3(x, 0.12, 0.73),
      )
      return eye
    })
    mesh(
      new THREE.CylinderGeometry(0.065, 0.065, 0.26, 16),
      metal,
      head,
      new THREE.Vector3(0, 0.78, 0),
    )
    mesh(new THREE.SphereGeometry(0.09, 16, 12), crimson, head, new THREE.Vector3(0, 0.94, 0))
    mesh(rounded(0.35, 0.1, 0.05, 0.04), charcoal, head, new THREE.Vector3(0, -0.28, 0.724))
    for (const side of [-1, 1]) {
      const ear = mesh(
        new THREE.CylinderGeometry(0.2, 0.2, 0.16, 24),
        metal,
        head,
        new THREE.Vector3(side * 0.9, -0.03, 0),
      )
      ear.rotation.z = Math.PI / 2
      mesh(
        new THREE.SphereGeometry(0.16, 24, 16),
        charcoal,
        group,
        new THREE.Vector3(side * 0.66, -0.83, 0),
      )
      const arm = mesh(
        rounded(0.24, 0.57, 0.3, 0.11),
        metal,
        group,
        new THREE.Vector3(side * 0.68, -1.05, 0.05),
      )
      arm.rotation.z = side * -0.25
      mesh(
        new THREE.SphereGeometry(0.16, 24, 16),
        metal,
        group,
        new THREE.Vector3(side * 0.78, -1.34, 0.06),
      )
      mesh(rounded(0.28, 0.18, 0.43, 0.08), metal, group, new THREE.Vector3(side * 0.3, -1.55, 0.1))
    }
    mesh(
      new THREE.CylinderGeometry(0.14, 0.14, 0.18, 20),
      charcoal,
      group,
      new THREE.Vector3(0, -0.72, 0),
    )
    mesh(rounded(1.06, 0.7, 0.82, 0.2), metal, group, new THREE.Vector3(0, -1.09, 0))
    mesh(rounded(0.65, 0.38, 0.06, 0.09), glass, group, new THREE.Vector3(0, -1.05, 0.421))
    mesh(
      new THREE.TorusGeometry(0.12, 0.03, 10, 30),
      crimson,
      group,
      new THREE.Vector3(0, -1.05, 0.46),
    )
    return { group, head, eyes }
  }

  const robots: { object: ReturnType<typeof robot>; base: THREE.Vector3; offset: number }[] = []
  if (mode === 'pipeline') {
    const object = robot()
    object.group.scale.setScalar(0.78)
    object.group.position.set(0.9, 1.85, -1.2)
    object.group.rotation.y = 0.1
    object.group.rotation.z = -0.1
    scene.add(object.group)
    robots.push({ object, base: object.group.position.clone(), offset: 0 })
  } else {
    for (let i = 0; i < 3; i++) {
      const object = robot()
      object.group.scale.setScalar([0.78, 0.71, 0.66][i])
      object.group.position.set([0.5, -0.45, 0.4][i], [1.85, 0.1, -1.48][i], [-0.55, 0.35, 1][i])
      object.group.rotation.y = [0.1, -0.2, 0.25][i]
      object.group.rotation.z = [-0.11, 0.12, -0.16][i]
      scene.add(object.group)
      robots.push({ object, base: object.group.position.clone(), offset: i * 1.8 })
    }
  }

  const animated: {
    object: THREE.Group
    path: THREE.CatmullRomCurve3
    offset: number
    output: boolean
  }[] = []
  let liquid: THREE.ShaderMaterial | undefined
  if (mode === 'pipeline') {
    const portal = new THREE.Group()
    portal.position.y = -0.45
    scene.add(portal)
    mesh(
      new THREE.CylinderGeometry(1.48, 1.38, 0.24, 80),
      charcoal,
      portal,
      new THREE.Vector3(0, -0.13, 0),
    )
    for (const [radius, width, material, y] of [
      [1.39, 0.085, metal, 0],
      [1.3, 0.029, sensorRed, 0.025],
      [1.49, 0.011, crimson, -0.14],
    ] as const) {
      const ring = mesh(
        new THREE.TorusGeometry(radius, width, 16, 90),
        material,
        portal,
        new THREE.Vector3(0, y, 0),
      )
      ring.rotation.x = -Math.PI / 2
    }
    liquid = new THREE.ShaderMaterial({
      uniforms: { uTime: { value: 0 } },
      vertexShader:
        'varying vec2 vUv; void main(){ vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }',
      fragmentShader: `varying vec2 vUv; uniform float uTime;
        void main(){ vec2 p=(vUv-.5)*2.; float r=length(p); float a=atan(p.y,p.x);
        float wave=sin(a*5.+uTime*.8)+sin(p.x*5.-uTime)*.5;
        float edge=.74+wave*.035; float shape=1.-smoothstep(edge-.025,edge+.025,r);
        float highlight=pow(max(0.,1.-abs(r-edge)),36.);
        vec3 base=mix(vec3(.04,.005,.007),vec3(.65,.06,.09),shape);
        base+=shape*vec3(.4,.2,.2)*(sin(p.x*3.+p.y*3.+uTime*.5)*.25+.45);
        base+=highlight*vec3(.9,.12,.16); gl_FragColor=vec4(base,1.); }`,
      side: THREE.DoubleSide,
    })
    const pool = mesh(
      new THREE.CircleGeometry(1.27, 90),
      liquid,
      portal,
      new THREE.Vector3(0, -0.015, 0),
    )
    pool.rotation.x = -Math.PI / 2

    const input = new THREE.CatmullRomCurve3([
      new THREE.Vector3(-3.9, 0.55, -2.8),
      new THREE.Vector3(-3.2, 0.35, -1.4),
      new THREE.Vector3(-2.55, 0.06, 0.35),
      new THREE.Vector3(-1.72, -0.18, 0.93),
      new THREE.Vector3(-1.18, -0.42, 0.18),
    ])
    const output = new THREE.CatmullRomCurve3([
      new THREE.Vector3(0.16, -1.13, 0.25),
      new THREE.Vector3(1.55, -1.3, 0.95),
      new THREE.Vector3(2.7, -1.15, 1.8),
      new THREE.Vector3(3.8, -0.77, 2.8),
    ])
    function conveyor(path: THREE.CatmullRomCurve3) {
      const vertices: number[] = []
      const indices: number[] = []
      for (let i = 0; i <= 60; i++) {
        const point = path.getPointAt(i / 60)
        const sideways = new THREE.Vector3(0, 1, 0).cross(path.getTangentAt(i / 60)).normalize()
        for (let j = 0; j <= 4; j++) {
          const p = point.clone().addScaledVector(sideways, (j / 4 - 0.5) * 1.12)
          vertices.push(p.x, p.y, p.z)
          if (i < 60 && j < 4) {
            const k = i * 5 + j
            indices.push(k, k + 5, k + 1, k + 1, k + 5, k + 6)
          }
        }
      }
      const geometry = new THREE.BufferGeometry()
      geometry.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3))
      geometry.setIndex(indices)
      geometry.computeVertexNormals()
      mesh(
        geometry,
        new THREE.MeshStandardMaterial({
          color: '#1b1d1d',
          roughness: 0.58,
          metalness: 0.73,
          side: THREE.DoubleSide,
        }),
        scene,
      )
      scene.add(
        new THREE.LineSegments(
          new THREE.WireframeGeometry(geometry),
          new THREE.LineBasicMaterial({ color: '#828888', transparent: true, opacity: 0.2 }),
        ),
      )
      for (const side of [-1, 1]) {
        const points = Array.from({ length: 35 }, (_, i) => {
          const p = path.getPointAt(i / 34)
          const tangent = path.getTangentAt(i / 34)
          return p.addScaledVector(
            new THREE.Vector3(0, 1, 0).cross(tangent).normalize(),
            side * 0.58,
          )
        })
        tube(points, 0.018, charcoal, scene)
      }
    }
    conveyor(input)
    conveyor(output)
    function token(output: boolean) {
      const group = new THREE.Group()
      const coin = mesh(new THREE.CylinderGeometry(0.34, 0.34, 0.13, 40), charcoal, group)
      coin.rotation.x = Math.PI / 2
      mesh(
        new THREE.TorusGeometry(0.33, 0.025, 12, 50),
        output ? pearl : metal,
        group,
        new THREE.Vector3(0, 0, 0.065),
      )
      mesh(new THREE.CircleGeometry(0.29, 40), glass, group, new THREE.Vector3(0, 0, 0.071))
      const observationPoints = [
        [-0.14, 0.15],
        [-0.14, -0.06],
        [-0.11, -0.13],
        [-0.04, -0.17],
        [0.05, -0.16],
        [0.1, -0.1],
        [0.1, 0.01],
      ]
      tube(
        observationPoints.map(([x, y]) => new THREE.Vector3(x, y, 0.084)),
        0.023,
        output ? pearl : metal,
        group,
      )
      if (output)
        tube(
          [new THREE.Vector3(-0.01, 0.04, 0.09), new THREE.Vector3(0.13, 0.17, 0.09)],
          0.022,
          crimson,
          group,
        )
      else
        for (let i = 0; i < 3; i++)
          mesh(
            rounded(0.1, 0.018, 0.017, 0.005),
            metal,
            group,
            new THREE.Vector3(0, 0.07 - i * 0.056, 0.085),
          )
      scene.add(group)
      if (output) {
        tube(
          [new THREE.Vector3(0.04, 0.17, 0.09), new THREE.Vector3(0.13, 0.17, 0.09)],
          0.022,
          crimson,
          group,
        )
        tube(
          [new THREE.Vector3(0.13, 0.17, 0.09), new THREE.Vector3(0.13, 0.08, 0.09)],
          0.022,
          crimson,
          group,
        )
      }
      return group
    }
    for (let i = 0; i < 4; i++) {
      animated.push({ object: token(false), path: input, offset: i / 4, output: false })
      animated.push({ object: token(true), path: output, offset: i / 4, output: true })
    }
  }

  // Small background points provide depth, with deterministic positions for replayable artwork.
  const points = Array.from({ length: 50 }, (_, i) => [
    Math.sin(i * 11.3) * 5,
    Math.cos(i * 3.7) * 3,
    -4 - (i % 5),
  ]).flat()
  const particles = new THREE.BufferGeometry()
  particles.setAttribute('position', new THREE.Float32BufferAttribute(points, 3))
  scene.add(
    new THREE.Points(
      particles,
      new THREE.PointsMaterial({ color: '#a97d7d', size: 0.018, transparent: true, opacity: 0.45 }),
    ),
  )
  const pointer = new THREE.Vector2()
  const onPointer = (event: PointerEvent) => {
    const rect = container.getBoundingClientRect()
    pointer.set(
      (event.clientX - rect.left) / rect.width - 0.5,
      (event.clientY - rect.top) / rect.height - 0.5,
    )
  }
  const onLeave = () => pointer.set(0, 0)
  container.addEventListener('pointermove', onPointer)
  container.addEventListener('pointerleave', onLeave)
  function draw() {
    const motion = !reducedMotion.matches && !motionPaused
    robots.forEach(({ object, base, offset }) => {
      object.group.position.y = base.y + Math.sin(time * 0.8 + offset) * 0.09
      object.head.rotation.z = Math.sin(time * 0.6 + offset) * 0.065
      object.group.rotation.y =
        0.16 + Math.sin(time * 0.45 + offset) * 0.17 + (motion ? pointer.x * 0.2 : 0)
      const blink = motion && Math.sin(time * 1.7 + offset) > 0.987 ? 0.18 : 1
      object.eyes.forEach((eye) => {
        eye.scale.y = blink
      })
    })
    animated.forEach(({ object, path, offset, output }) => {
      const t = (time * 0.095 + offset) % 1
      object.position.copy(path.getPointAt(t))
      object.position.y += 0.37
      object.rotation.y = time * 0.65 + offset * Math.PI
      const scale = output ? Math.min(1, t * 9, (1 - t) * 12) : Math.min(1, t * 12, (1 - t) * 9)
      object.scale.setScalar(Math.max(0.01, scale))
    })
    if (liquid) liquid.uniforms.uTime.value = time
    composer.render()
  }
  function animate(now: number) {
    if (!running || disposed) return
    time += previous ? Math.min((now - previous) / 1000, 0.08) : 0
    previous = now
    draw()
    frame = requestAnimationFrame(animate)
  }
  function sync() {
    const shouldRun =
      visible &&
      contextAvailable &&
      !document.hidden &&
      !reducedMotion.matches &&
      !motionPaused &&
      !disposed
    if (shouldRun && !running) {
      running = true
      previous = 0
      frame = requestAnimationFrame(animate)
    } else if (!shouldRun) {
      running = false
      cancelAnimationFrame(frame)
      if (!disposed && contextAvailable) draw()
    }
  }
  function resize() {
    if (disposed) return
    const { width, height } = container.getBoundingClientRect()
    if (!width || !height) return
    const aspect = width / height
    const h = mode === 'pipeline' ? Math.max(6.6, 7.2 / aspect) : Math.max(6.8, 4.6 / aspect)
    camera.left = (-h * aspect) / 2
    camera.right = (h * aspect) / 2
    camera.top = h / 2
    camera.bottom = -h / 2
    camera.updateProjectionMatrix()
    renderer.setSize(width, height)
    composer.setSize(width, height)
    draw()
  }
  const resizeObserver = new ResizeObserver(resize)
  resizeObserver.observe(container)
  const observer = new IntersectionObserver(
    (entries) => {
      visible = entries[0].isIntersecting
      sync()
    },
    { rootMargin: '60px' },
  )
  observer.observe(container)
  document.addEventListener('visibilitychange', sync)
  reducedMotion.addEventListener('change', sync)
  const contextLost = (event: Event) => {
    event.preventDefault()
    contextAvailable = false
    running = false
    cancelAnimationFrame(frame)
    container.dataset.render = 'fallback'
  }
  const contextRestored = () => {
    contextAvailable = true
    container.dataset.render = 'ready'
    resize()
    sync()
  }
  renderer.domElement.addEventListener('webglcontextlost', contextLost)
  renderer.domElement.addEventListener('webglcontextrestored', contextRestored)
  resize()
  container.dataset.render = 'ready'
  return {
    setPaused(paused: boolean) {
      motionPaused = paused
      sync()
    },
    dispose() {
      disposed = true
      running = false
      cancelAnimationFrame(frame)
      observer.disconnect()
      resizeObserver.disconnect()
      document.removeEventListener('visibilitychange', sync)
      reducedMotion.removeEventListener('change', sync)
      container.removeEventListener('pointermove', onPointer)
      container.removeEventListener('pointerleave', onLeave)
      renderer.domElement.removeEventListener('webglcontextlost', contextLost)
      renderer.domElement.removeEventListener('webglcontextrestored', contextRestored)
      const geometries = new Set<THREE.BufferGeometry>()
      const materials = new Set<THREE.Material>()
      scene.traverse((object) => {
        if (
          object instanceof THREE.Mesh ||
          object instanceof THREE.LineSegments ||
          object instanceof THREE.Points
        ) {
          geometries.add(object.geometry)
          const material = object.material
          for (const m of Array.isArray(material) ? material : [material]) materials.add(m)
        }
      })
      geometries.forEach((g) => g.dispose())
      materials.forEach((m) => m.dispose())
      environmentTarget.dispose()
      bloom.dispose()
      composer.dispose()
      renderer.dispose()
      renderer.forceContextLoss()
      renderer.domElement.remove()
    },
  }
}
