/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#07111f',
        panel: '#0d1a2b',
        line: '#1d3046',
        cyan: '#37d6d0',
        signal: '#ffb454',
      },
      boxShadow: {
        console: '0 18px 50px rgba(0, 0, 0, 0.28)',
      },
      backgroundImage: {
        'console-grid': 'linear-gradient(rgba(79, 116, 145, 0.07) 1px, transparent 1px), linear-gradient(90deg, rgba(79, 116, 145, 0.07) 1px, transparent 1px)',
      },
    },
  },
  plugins: [],
};
